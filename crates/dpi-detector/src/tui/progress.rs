//! Live one-line progress on stderr: the counter line, the thread that keeps its
//! clock moving, and the spinner for phases without a total.

use dpi_core::ProgressBlock;
use std::io::{IsTerminal, Write};
use std::sync::{Arc, Mutex, Weak};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::tui::backend::has_vt;

struct BlockState {
    /// Canonical protocol token (rule 4), empty for a single-counter phase.
    token: &'static str,
    done: usize,
    total: usize,
}

struct ProgressState {
    desc: String,
    blocks: Vec<BlockState>,
    started: Instant,
    /// Width of the last drawn line, so a shrinking counter cannot leave
    /// digits behind on the terminal.
    drawn: usize,
}

/// How often the line is redrawn while nothing finishes, so the elapsed clock
/// keeps moving and a slow unit does not make the phase look hung.
const REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// `mm:ss`, or `h:mm:ss` past the hour.
fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else {
        format!("{:02}:{:02}", s / 60, s % 60)
    }
}

/// One progress line: `desc  12/50 · 00:07`. A multi-block phase (test 1) shows
/// every counter that is running at the same time instead —
/// `DNS  UDP 12/50 · DoH 2/37 · DoT 0/34 · EGRESS 5/50 · 00:31` — because the
/// blocks overlap and no single sequential counter describes them. Only the
/// elapsed clock is drawn, never an estimate: per-unit cost differs by an order
/// of magnitude across blocks, so a projected rate would lie. The trailing
/// ellipsis of the phase descriptions is dropped, the live numbers already say
/// "running".
fn progress_line(desc: &str, blocks: &[BlockState], elapsed: Duration) -> String {
    let mut line = desc.trim_end_matches(['.', ' ']).to_string();
    if blocks.len() == 1 && blocks[0].token.is_empty() {
        line.push_str(&format!("  {}/{}", blocks[0].done, blocks[0].total));
    } else if !blocks.is_empty() {
        let counters: Vec<String> = blocks
            .iter()
            .map(|b| format!("{} {}/{}", b.token, b.done, b.total))
            .collect();
        line.push_str("  ");
        line.push_str(&counters.join(" · "));
    }
    line.push_str(&format!(" · {}", fmt_dur(elapsed)));
    line
}

/// A timer that redraws the line while a phase runs.
struct Refresher {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Refresher {
    fn idle() -> Self {
        Self { stop: Arc::new(AtomicBool::new(false)), handle: None }
    }
}

/// Live one-line progress on stderr, redrawn in place while a phase runs.
/// Draws only when stderr is a TTY; silent otherwise so pipes and the report
/// file stay byte-clean.
pub struct LiveProgress {
    state: Mutex<ProgressState>,
    /// Weak self-reference for the refresher thread (never a cycle).
    me: Mutex<Weak<LiveProgress>>,
    refresher: Mutex<Refresher>,
    tty: bool,
}

impl LiveProgress {
    pub fn new() -> Arc<Self> {
        let live = Arc::new(Self {
            state: Mutex::new(ProgressState {
                desc: String::new(),
                blocks: Vec::new(),
                started: Instant::now(),
                drawn: 0,
            }),
            me: Mutex::new(Weak::new()),
            refresher: Mutex::new(Refresher::idle()),
            tty: std::io::stderr().is_terminal(),
        });
        if let Ok(mut me) = live.me.lock() {
            *me = Arc::downgrade(&live);
        }
        live
    }

    /// Starts a single-counter phase: resets the counter and its clock.
    pub fn set(&self, desc: String, total: usize) {
        self.start(desc, vec![BlockState { token: "", done: 0, total }]);
    }

    /// Starts a sequential run of stages that share one line (test 2: DNS →
    /// TLS 1.3 → TLS 1.2 → HTTP): every stage keeps its own counter, the
    /// counters already finished stay on screen and the clock spans the whole
    /// run instead of restarting at each stage.
    pub fn begin_stages(&self, desc: String, stages: &[(ProgressBlock, usize)]) {
        self.start(
            desc,
            stages
                .iter()
                .map(|(block, total)| BlockState { token: block.token(), done: 0, total: *total })
                .collect(),
        );
    }

    /// Corrects the total of a stage that is already on the line, for when its
    /// phase reports the count it actually iterates.
    pub fn set_total(&self, block: ProgressBlock, total: usize) {
        let changed = match self.state.lock() {
            Ok(mut st) => match st.blocks.iter_mut().find(|b| b.token == block.token()) {
                Some(b) if b.total != total => {
                    b.total = total;
                    true
                }
                _ => false,
            },
            Err(_) => false,
        };
        if changed {
            self.draw();
        }
    }

    /// Starts a phase whose blocks run concurrently and are all reported.
    pub fn set_blocks(&self, desc: String, blocks: &[(ProgressBlock, usize)]) {
        self.start(
            desc,
            blocks
                .iter()
                .map(|(block, total)| BlockState { token: block.token(), done: 0, total: *total })
                .collect(),
        );
    }

    fn start(&self, desc: String, blocks: Vec<BlockState>) {
        if let Ok(mut st) = self.state.lock() {
            st.desc = desc;
            st.blocks = blocks;
            st.started = Instant::now();
        }
        self.start_refresher();
        self.draw();
    }

    /// Advances the single counter of the current phase.
    pub fn tick(&self) {
        if self.bump_first() {
            self.draw();
        }
    }

    /// Advances the counter of `block` in a multi-block phase.
    pub fn bump(&self, block: ProgressBlock) {
        let advanced = match self.state.lock() {
            Ok(mut st) => match st.blocks.iter_mut().find(|b| b.token == block.token()) {
                Some(b) => {
                    b.done += 1;
                    true
                }
                None => false,
            },
            Err(_) => false,
        };
        if advanced {
            self.draw();
        }
    }

    fn bump_first(&self) -> bool {
        match self.state.lock() {
            Ok(mut st) => match st.blocks.first_mut() {
                Some(b) => {
                    b.done += 1;
                    true
                }
                None => false,
            },
            Err(_) => false,
        }
    }

    /// Clears the line and stops redrawing (transient: nothing remains).
    pub fn finish(&self) {
        self.stop_refresher();
        if !self.tty {
            return;
        }
        let drawn = self.state.lock().map(|st| st.drawn).unwrap_or(0);
        if has_vt() {
            eprint!("\x1b[2K\r");
        } else {
            eprint!("\r{}\r", " ".repeat(drawn.max(79)));
        }
        let _ = std::io::stderr().flush();
    }

    fn start_refresher(&self) {
        if !self.tty {
            return;
        }
        self.stop_refresher();
        let weak = match self.me.lock() {
            Ok(me) => me.clone(),
            Err(_) => return,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                std::thread::sleep(REFRESH_INTERVAL);
                if stop_c.load(Ordering::SeqCst) {
                    break;
                }
                match weak.upgrade() {
                    Some(live) => live.draw(),
                    None => break,
                }
            }
        });
        if let Ok(mut r) = self.refresher.lock() {
            *r = Refresher { stop, handle: Some(handle) };
        }
    }

    fn stop_refresher(&self) {
        let old = match self.refresher.lock() {
            Ok(mut r) => std::mem::replace(&mut *r, Refresher::idle()),
            Err(_) => return,
        };
        old.stop.store(true, Ordering::SeqCst);
        if let Some(h) = old.handle {
            let _ = h.join();
        }
    }

    fn draw(&self) {
        if !self.tty {
            return;
        }
        if let Ok(mut st) = self.state.lock() {
            let elapsed = st.started.elapsed();
            let text = progress_line(&st.desc, &st.blocks, elapsed);
            // Pad over the tail of a longer previous line before parking the
            // cursor: `\r` alone only moves it, it does not erase.
            let width = text.chars().count();
            let pad = st.drawn.saturating_sub(width);
            eprint!("\r  {}{}", text, " ".repeat(pad));
            let _ = std::io::stderr().flush();
            st.drawn = width;
        }
    }
}

/// Indeterminate spinner for phases without a total: frames `- \ | /`,
/// redrawn on stderr every 120 ms.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    tty: bool,
}

impl Spinner {
    pub fn start(desc: &str) -> Self {
        let tty = std::io::stderr().is_terminal();
        let stop = Arc::new(AtomicBool::new(false));
        let handle = if tty {
            let stop_c = Arc::clone(&stop);
            let desc = desc.to_string();
            Some(std::thread::spawn(move || {
                let frames = ["-", "\\", "|", "/"];
                let mut i = 0;
                while !stop_c.load(Ordering::SeqCst) {
                    eprint!("\r  {} {}   ", desc, frames[i % 4]);
                    let _ = std::io::stderr().flush();
                    i += 1;
                    std::thread::sleep(Duration::from_millis(120));
                }
            }))
        } else {
            None
        };
        Self { stop, handle, tty }
    }

    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        if self.tty {
            if has_vt() {
                eprint!("\x1b[2K\r");
            } else {
                eprint!("\r                                                                               \r");
            }
            let _ = std::io::stderr().flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// The live line is what the user watches during a run: a single-counter
    /// phase names the unit and estimates the remainder while there is one, and
    /// a multi-block phase shows every counter that is running at once.
    #[test]
    fn progress_line_single_and_blocks() {
        let one = [BlockState { token: "", done: 12, total: 50 }];
        assert_eq!(
            progress_line("Проверка... ", &one, Duration::from_secs(7)),
            "Проверка  12/50 · 00:07"
        );
        // The counter and clock are drawn in every state, 0/total included.
        let start = [BlockState { token: "", done: 0, total: 50 }];
        assert_eq!(progress_line("X", &start, Duration::from_secs(3)), "X  0/50 · 00:03");
        let done = [BlockState { token: "", done: 50, total: 50 }];
        assert_eq!(progress_line("X", &done, Duration::from_secs(60)), "X  50/50 · 01:00");

        // Test 1: four blocks, one line, elapsed only (per-unit cost differs by
        // an order of magnitude between blocks, so no aggregate estimate).
        let blocks = [
            BlockState { token: "UDP", done: 12, total: 50 },
            BlockState { token: "DoH", done: 2, total: 37 },
            BlockState { token: "DoT", done: 0, total: 34 },
            BlockState { token: "EGRESS", done: 5, total: 50 },
        ];
        assert_eq!(
            progress_line("DNS", &blocks, Duration::from_secs(31)),
            "DNS  UDP 12/50 · DoH 2/37 · DoT 0/34 · EGRESS 5/50 · 00:31"
        );

        assert_eq!(fmt_dur(Duration::from_secs(3661)), "1:01:01");
        assert_eq!(fmt_dur(Duration::from_secs(59)), "00:59");
    }
}
