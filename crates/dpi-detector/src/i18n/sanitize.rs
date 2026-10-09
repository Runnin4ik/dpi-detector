//! Drops the escape sequences and control bytes a peer can put into text the
//! report prints.
//!
//! The engine hands the display layer values it did not author: a redirect's
//! `Location` host, a TLS alert's wording, an HTTP status line, a certificate
//! field, a resolver's provider name. Any of them can carry `ESC`, and the
//! terminal acts on it.
//!
//! The failure this closes: a server that answered `302` with
//! `Location: http://evil\x1b]0;PWNED\x07.example/` reached the terminal with
//! the `OSC 0` intact, so a probe could set the window title of the machine
//! running it. The same hole carried `OSC 8` (a clickable hyperlink pointing
//! wherever the server liked), `\x1b[?25l` (hide the cursor) and `\x1b[?1049h`
//! (switch the screen buffer). `strip_ansi` was no defence: it only recognises
//! a sequence that ends in an ASCII letter, and the colour mode the terminal
//! normally runs in never called it at all. `parse_host`'s
//! `to_ascii_lowercase()` happens to neuter uppercase CSI finals such as
//! `\x1b[2J`, but not one of the four above.
//!
//! Sanitizing here, in the layer that turns a value into display text, is what
//! keeps the UI's own escapes intact: `tui::clean_output` is a *mode* filter
//! over rows the screens build with deliberate colour, so stripping controls
//! there would repaint the interface in monochrome. `--json` keeps the raw
//! bytes — this is display text, and Rule 5 says the machine channel is not the
//! place to launder a value.

/// Drops every escape sequence and control byte from `s`.
///
/// Whole sequences go, not just the `ESC`: a consumed `OSC` leaves no
/// `]0;pwned` debris behind. Whatever control byte survives is dropped too, tab
/// excepted — it is the one a report line may legitimately carry.
pub(crate) fn sanitize_peer_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                // CSI: parameters and intermediates, then one final byte 0x40..=0x7E.
                Some('[') => {
                    chars.next();
                    while let Some(&n) = chars.peek() {
                        chars.next();
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                }
                // OSC: the payload runs to BEL or to ST (`ESC \`).
                Some(']') => {
                    chars.next();
                    while let Some(n) = chars.next() {
                        if n == '\x07' {
                            break;
                        }
                        if n == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                // DCS/SOS/PM/APC: string payloads, terminated by ST only.
                Some('P' | 'X' | '^' | '_') => {
                    chars.next();
                    while let Some(n) = chars.next() {
                        if n == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                // A two-character escape (`ESC c`, `ESC ( B`): drop the pair.
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
            continue;
        }

        let cp = c as u32;
        let control = (cp < 0x20 && c != '\t') || cp == 0x7f || (0x80..=0x9f).contains(&cp);
        if !control {
            out.push(c);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four sequences a poisoned `Location` was measured carrying, plus the
    /// plain control bytes, must all be gone.
    #[test]
    fn a_peer_escape_sequence_never_survives() {
        for (poisoned, want) in [
            ("evil\x1b]0;PWNED\x07.example", "evil.example"),
            ("\x1b]8;;http://evil\x07link", "link"),
            ("x\x1b[?25l.attacker.example", "x.attacker.example"),
            ("x\x1b[?1049h.example", "x.example"),
            ("x\x1b[2J\x1b[H.example", "x.example"),
            ("a\x08b\x7fc\x0bd\x0ce", "abcde"),
            ("nel\u{85}and\u{9b}csi", "nelandcsi"),
            ("keep\tthe\ttabs", "keep\tthe\ttabs"),
            ("plain.example", "plain.example"),
        ] {
            assert_eq!(sanitize_peer_text(poisoned), want, "input {poisoned:?}");
        }
    }

    /// A stray `ESC` and a sequence the peer never terminated must not eat the
    /// text that follows: the report still has to name the host it stopped at.
    #[test]
    fn a_broken_sequence_stops_at_its_end() {
        assert_eq!(sanitize_peer_text("a\x1b"), "a");
        assert_eq!(sanitize_peer_text("a\x1b]unterminated"), "a");
        assert_eq!(sanitize_peer_text("a\x1b[1;2"), "a");
        assert_eq!(sanitize_peer_text("a\x1bPdcs\x1b\\b"), "ab");
    }
}
