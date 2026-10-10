//! One module per interactive screen, plus the post-run key read they share.

pub(crate) mod burst;
pub(crate) mod legend;
pub(crate) mod main;
pub(crate) mod post_run;

use crate::i18n::{Language, format_bidi};

/// One keycap: the key as it is drawn, and the background its chip carries.
///
/// The three colours are the footer's own vocabulary — cyan for a key that
/// moves the cursor, green for the one that starts the run, red for the one that
/// leaves — and they are `\x1b[1;<bg>;37m`, white on that background.
pub(crate) type Keycap = (&'static str, &'static str, &'static str);

/// The footer of a settings screen: one chip per key, its label after it.
///
/// The main menu and the burst settings draw the same row with a different key
/// set, and each carried its own copy of the chip escapes, the plain-mode
/// bracket form and the spacing between them. The row is what has to fit an
/// 80-column console — the Farsi footer is the longest — so a change to the
/// style was a change to two widths, measured twice.
///
/// `plain` is passed in rather than read from the global so both branches can be
/// measured in tests.
pub(crate) fn keycap_row(lang: Language, plain: bool, keys: &[Keycap]) -> String {
    keys.iter()
        .map(|(key, label, bg)| {
            let label = format_bidi(label, lang);
            if plain {
                // Brackets delimit the key where the coloured branch uses a
                // chip; no bar separators, so every glyph in the footer is
                // ASCII outside ascii mode.
                format!("[{key}] {label}")
            } else {
                // The chips carry a padding space of their own, so a single
                // plain space keeps the same visual gap while staying inside 80
                // columns.
                format!("\x1b[1;{bg};37m {key} \x1b[0m {label}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chip carries its key padded by one space either side, and the plain
    /// form brackets it — the two shapes the footers are built from.
    #[test]
    fn a_keycap_row_is_chips_or_brackets() {
        let keys: &[Keycap] = &[("0-7", "tests", "46"), ("Q", "quit", "41")];
        assert_eq!(
            keycap_row(Language::En, false, keys),
            "\x1b[1;46;37m 0-7 \x1b[0m tests \x1b[1;41;37m Q \x1b[0m quit"
        );
        assert_eq!(keycap_row(Language::En, true, keys), "[0-7] tests [Q] quit");
        assert!(keycap_row(Language::En, true, &[]).is_empty());
    }
}
