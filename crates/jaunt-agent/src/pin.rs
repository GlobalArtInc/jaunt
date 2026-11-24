use std::str::FromStr;

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const PREFIX: &str = "sha256:";
const DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinError {
    #[error("a CA pin must be sha256: followed by 64 hexadecimal digits")]
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaPin([u8; DIGEST_LEN]);

impl CaPin {
    pub fn matches(&self, root_der: &[u8]) -> bool {
        let digest = Sha256::digest(root_der);
        digest.as_slice().ct_eq(&self.0).into()
    }
}

impl FromStr for CaPin {
    type Err = PinError;

    fn from_str(text: &str) -> Result<Self, PinError> {
        let hex = text.strip_prefix(PREFIX).unwrap_or(text);
        if hex.len() != DIGEST_LEN * 2 {
            return Err(PinError::Malformed);
        }
        let mut digest = [0_u8; DIGEST_LEN];
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (slot, [high, low]) in digest.iter_mut().zip(pairs) {
            let high = hex_value(*high).ok_or(PinError::Malformed)?;
            let low = hex_value(*low).ok_or(PinError::Malformed)?;
            *slot = (high << 4) | low;
        }
        Ok(Self(digest))
    }
}

fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{CaPin, PinError};
    use crate::keys::sha256_hex;

    #[test]
    fn pins_parse_with_or_without_the_prefix_and_match_only_the_pinned_root() {
        let root = b"root certificate der";
        let hex = sha256_hex(root);
        for text in [
            format!("sha256:{hex}"),
            hex.clone(),
            format!("sha256:{}", hex.to_ascii_uppercase()),
        ] {
            let pin: CaPin = text.parse().unwrap();
            assert!(pin.matches(root), "{text}");
            assert!(!pin.matches(b"another root"), "{text}");
        }
    }

    #[test]
    fn a_pin_differing_in_the_first_or_last_digit_does_not_match() {
        let root = b"root certificate der";
        let hex = sha256_hex(root);
        let flip = |digit: char| if digit == '0' { '1' } else { '0' };
        let mut first = hex.clone();
        first.replace_range(..1, &flip(hex.chars().next().unwrap()).to_string());
        let mut last = hex.clone();
        last.replace_range(63.., &flip(hex.chars().last().unwrap()).to_string());
        for text in [first, last] {
            let pin: CaPin = text.parse().unwrap();
            assert!(!pin.matches(root), "{text}");
        }
    }

    #[test]
    fn malformed_pins_are_refused() {
        let hex = sha256_hex(b"x");
        for text in [
            String::new(),
            "sha256:".to_owned(),
            format!("sha256:{}", &hex[1..]),
            format!("sha256:{hex}0"),
            format!("sha256:{}g", &hex[1..]),
            format!("sha1:{hex}"),
            format!("SHA256:{hex}"),
            format!(" {hex}"),
        ] {
            assert_eq!(text.parse::<CaPin>(), Err(PinError::Malformed), "{text}");
        }
    }
}
