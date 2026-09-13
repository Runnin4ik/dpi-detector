//! Keyboard input: the IME width fold and the physical-key mapping every screen
//! resolves a key through, so the same key works on every layout.


pub fn normalize_key_char(c: char) -> char {
    // Fullwidth ASCII (Chinese, Japanese, Korean IME 全角: ｑ -> q, １ -> 1, etc.)
    if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        return char::from_u32(c as u32 - 0xFEE0).unwrap_or(c);
    }
    if c == '\u{3000}' {
        return ' ';
    }
    c
}

/// The Latin key at the same physical position, for the layouts the menus answer
/// to: Russian/Ukrainian, Persian/Arabic, Bopomofo and Hebrew.
///
/// Navigation is written in Latin (`w`/`a`/`s`/`d`, Vim `hjkl`, `r`/`m`/`x`), and
/// every screen has to answer the same physical key on every layout. Mapping it
/// once here is what keeps the screens consistent: the alternative — listing the
/// non-Latin characters in each `match` — is how the burst-settings screen came
/// to accept only Latin keys while the menu accepted six layouts.
pub(crate) fn latin_key(c: char) -> char {
    match c {
        // Russian / Ukrainian: ц(w) ы(s) ф(a) в(d) й(q) к(r) ч(x) п(g) м(m) ь(m)
        // л(k) р(h) о(j) д(l) і(s)
        'ц' | 'Ц' => 'w',
        'ы' | 'Ы' | 'і' | 'І' => 's',
        'ф' | 'Ф' => 'a',
        'в' | 'В' => 'd',
        'й' | 'Й' => 'q',
        'к' | 'К' => 'r',
        'ч' | 'Ч' => 'x',
        'п' | 'П' => 'g',
        'м' | 'М' | 'ь' | 'Ь' => 'm',
        'л' | 'Л' => 'k',
        'р' | 'Р' => 'h',
        'о' | 'О' => 'j',
        'д' | 'Д' => 'l',
        // Persian / Arabic
        'ص' => 'w',
        'س' => 's',
        'ش' => 'a',
        'ی' | 'ي' => 'd',
        'ض' => 'q',
        'ر' => 'r',
        'پ' | 'م' | 'ة' => 'm',
        // Bopomofo
        'ㄊ' => 'w',
        'ㄋ' => 's',
        'ㄇ' => 'a',
        'ㄎ' => 'd',
        'ㄆ' => 'q',
        'ㄐ' => 'r',
        'ㄩ' => 'm',
        // Hebrew
        'ד' => 's',
        'ש' => 'a',
        'ג' => 'd',
        'צ' => 'm',
        other => other,
    }
}

/// The character as key handling sees it: IME width folded to ASCII first, then
/// [`latin_key`].
pub fn nav_key(c: char) -> char {
    latin_key(normalize_key_char(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_normalize_key_char() {
        // Fullwidth letters to ASCII (Chinese / Japanese / Korean IME)
        assert_eq!(normalize_key_char('ｑ'), 'q');
        assert_eq!(normalize_key_char('Ｑ'), 'Q');
        assert_eq!(normalize_key_char('ｗ'), 'w');
        assert_eq!(normalize_key_char('ｓ'), 's');
        assert_eq!(normalize_key_char('ａ'), 'a');
        assert_eq!(normalize_key_char('ｄ'), 'd');
        assert_eq!(normalize_key_char('ｒ'), 'r');
        assert_eq!(normalize_key_char('ｍ'), 'm');

        // Fullwidth digits to ASCII
        assert_eq!(normalize_key_char('０'), '0');
        assert_eq!(normalize_key_char('１'), '1');
        assert_eq!(normalize_key_char('２'), '2');
        assert_eq!(normalize_key_char('６'), '6');

        // Fullwidth space
        assert_eq!(normalize_key_char('\u{3000}'), ' ');

        // Standard characters preserved
        assert_eq!(normalize_key_char('q'), 'q');
        assert_eq!(normalize_key_char('й'), 'й');
        assert_eq!(normalize_key_char('ض'), 'ض');
    }

    /// Navigation is answered by physical position: the burst-settings screen
    /// used to accept only Latin letters, so a user in a Cyrillic, Persian,
    /// Bopomofo or Hebrew layout could not move the cursor there even though the
    /// menu accepted the same keys.
    #[test]
    fn test_nav_key_covers_the_supported_layouts() {
        for (typed, key) in [
            // Russian / Ukrainian
            ('ц', 'w'),
            ('Ц', 'w'),
            ('ы', 's'),
            ('Ы', 's'),
            ('ф', 'a'),
            ('в', 'd'),
            ('й', 'q'),
            ('к', 'r'),
            ('ч', 'x'),
            ('п', 'g'),
            ('ь', 'm'),
            ('д', 'l'),
            ('і', 's'),
            ('л', 'k'),
            ('р', 'h'),
            ('о', 'j'),
            // Persian / Arabic
            ('ص', 'w'),
            ('س', 's'),
            ('ش', 'a'),
            ('ی', 'd'),
            ('ض', 'q'),
            ('ر', 'r'),
            ('ة', 'm'),
            // Bopomofo
            ('ㄊ', 'w'),
            ('ㄋ', 's'),
            ('ㄇ', 'a'),
            ('ㄎ', 'd'),
            ('ㄆ', 'q'),
            ('ㄐ', 'r'),
            ('ㄩ', 'm'),
            // Hebrew
            ('ד', 's'),
            ('ש', 'a'),
            ('ג', 'd'),
            ('צ', 'm'),
            // Fullwidth Latin goes through the IME fold first.
            ('ｗ', 'w'),
            ('ｑ', 'q'),
        ] {
            assert_eq!(nav_key(typed), key, "{typed} must answer as {key}");
        }

        // Latin keys and characters of no mapped layout stay as they are.
        for c in ['w', 'W', 'q', 'Q', 'x', 'ж', 'щ', 'ㄅ', '1', ' ', '-'] {
            assert_eq!(nav_key(c), c);
        }
    }
}
