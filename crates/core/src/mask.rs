//! Static read-path masking (milestone 7): `4111111111111111` → `************1111`.
//!
//! Masking runs after decryption/detokenization, on whatever the client would
//! otherwise see. It is enforced only for traffic through the proxy, and a
//! client that writes a masked value back stores the masked form — both
//! accepted trade-offs (see plans/PLAN.md).

/// A read-path mask: which characters stay visible and what replaces the rest.
///
/// With the `serde` feature it deserializes from `{ keep_last = 4 }` and the
/// like, `mask_with` defaulting to `*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize), serde(deny_unknown_fields))]
pub struct MaskSpec {
    /// Number of leading characters left visible.
    #[cfg_attr(feature = "serde", serde(default))]
    pub keep_first: usize,
    /// Number of trailing characters left visible.
    #[cfg_attr(feature = "serde", serde(default))]
    pub keep_last: usize,
    /// The character masked positions are replaced with.
    #[cfg_attr(feature = "serde", serde(default = "default_mask_with"))]
    pub mask_with: char,
}

#[cfg(feature = "serde")]
fn default_mask_with() -> char {
    '*'
}

impl MaskSpec {
    /// Masks a value, keeping the configured prefix/suffix. Values too short
    /// to have a hidden middle are masked entirely — keeping `keep_last = 4`
    /// of a 4-character value would reveal all of it.
    pub fn apply(&self, value: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(value) {
            Ok(s) => {
                let count = s.chars().count();
                if count <= self.keep_first + self.keep_last {
                    return self.mask_with.to_string().repeat(count).into_bytes();
                }
                s.chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if i < self.keep_first || i >= count - self.keep_last {
                            c
                        } else {
                            self.mask_with
                        }
                    })
                    .collect::<String>()
                    .into_bytes()
            }
            // Non-UTF-8 bytes: mask entirely rather than leak binary content.
            Err(_) => self.mask_with.to_string().repeat(value.len()).into_bytes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(keep_first: usize, keep_last: usize) -> MaskSpec {
        MaskSpec { keep_first, keep_last, mask_with: '*' }
    }

    #[test]
    fn masks_middle_keeping_edges() {
        assert_eq!(spec(0, 4).apply(b"4111111111111111"), b"************1111");
        assert_eq!(spec(2, 2).apply(b"secretive"), b"se*****ve");
        assert_eq!(spec(0, 0).apply(b"gone"), b"****");
    }

    #[test]
    fn short_values_are_fully_masked() {
        assert_eq!(spec(0, 4).apply(b"1234"), b"****");
        assert_eq!(spec(3, 3).apply(b"abcde"), b"*****");
        assert_eq!(spec(0, 4).apply(b""), b"");
    }

    #[test]
    fn masks_characters_not_bytes() {
        assert_eq!(spec(0, 1).apply("héllo".as_bytes()), "****o".as_bytes());
        // Invalid UTF-8 is fully masked, one mask char per byte.
        assert_eq!(spec(0, 2).apply(&[0xff, 0xfe, 0x41]), b"***");
    }

    #[cfg(feature = "keyfile")]
    #[test]
    fn parses_from_toml() {
        let mask: MaskSpec = toml::from_str("keep_last = 4\nmask_with = \"#\"").unwrap();
        assert_eq!(mask.keep_first, 0);
        assert_eq!(mask.keep_last, 4);
        assert_eq!(mask.mask_with, '#');
    }
}
