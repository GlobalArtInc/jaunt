use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};

use crate::token::{EntropyUnavailable, hash_secret};

const ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_LEN: usize = 8;
const GROUP_LEN: usize = 4;
const ACCEPT_BELOW: u8 = 248;
const DRAW_BYTES: usize = 16;
const MAX_DRAWS: usize = 16;
const MAX_TYPED_LEN: usize = 64;

fn symbol_for(byte: u8) -> Option<u8> {
    if byte >= ACCEPT_BELOW {
        return None;
    }
    ALPHABET.get(usize::from(byte) % ALPHABET.len()).copied()
}

pub(crate) fn generate() -> Result<String, EntropyUnavailable> {
    generate_from(&mut |buffer| OsRng.try_fill_bytes(buffer).map_err(|_| EntropyUnavailable))
}

fn generate_from(
    fill: &mut impl FnMut(&mut [u8]) -> Result<(), EntropyUnavailable>,
) -> Result<String, EntropyUnavailable> {
    let mut code = String::with_capacity(CODE_LEN);
    for _ in 0..MAX_DRAWS {
        let mut buffer = [0_u8; DRAW_BYTES];
        fill(&mut buffer)?;
        for byte in buffer {
            if let Some(symbol) = symbol_for(byte) {
                code.push(char::from(symbol));
                if code.len() == CODE_LEN {
                    return Ok(code);
                }
            }
        }
    }
    Err(EntropyUnavailable)
}

pub(crate) fn display(code: &str) -> String {
    let (head, tail) = code.split_at(code.len().min(GROUP_LEN));
    format!("{head}-{tail}")
}

pub(crate) fn normalize(typed: &str) -> Option<String> {
    if typed.len() > MAX_TYPED_LEN {
        return None;
    }
    let code: String = typed
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let valid = code.len() == CODE_LEN && code.bytes().all(|byte| ALPHABET.contains(&byte));
    valid.then_some(code)
}

pub(crate) fn hash(code: &str) -> String {
    hash_secret(code)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::token::EntropyUnavailable;

    use super::{ALPHABET, display, generate, generate_from, hash, normalize, symbol_for};

    #[test]
    fn the_alphabet_has_thirty_one_distinct_unambiguous_symbols() {
        let mut sorted = ALPHABET.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 31);
        for ambiguous in b"01ILOilo" {
            assert!(!ALPHABET.contains(ambiguous), "{}", char::from(*ambiguous));
        }
    }

    #[test]
    fn every_symbol_is_equally_likely_because_high_bytes_are_rejected() {
        let mut counts: BTreeMap<u8, usize> = BTreeMap::new();
        let mut rejected = 0;
        for byte in 0..=u8::MAX {
            match symbol_for(byte) {
                Some(symbol) => *counts.entry(symbol).or_default() += 1,
                None => rejected += 1,
            }
        }
        assert_eq!(counts.len(), 31);
        assert!(counts.values().all(|count| *count == 8), "{counts:?}");
        assert_eq!(rejected, 8);
    }

    #[test]
    fn generation_skips_rejected_bytes_and_stops_after_eight_symbols() {
        let mut fill = |buffer: &mut [u8]| {
            buffer.fill(255);
            buffer[1] = 0;
            buffer[3] = 30;
            buffer[4] = 31;
            buffer[5] = 247;
            buffer[7..11].fill(1);
            Ok(())
        };

        assert_eq!(generate_from(&mut fill).unwrap(), "2Z2Z3333");
    }

    #[test]
    fn generation_draws_again_when_a_draw_has_too_few_usable_bytes() {
        let mut calls = 0;
        let mut fill = |buffer: &mut [u8]| {
            calls += 1;
            if calls == 1 {
                buffer.fill(255);
                buffer[0] = 1;
            } else {
                buffer.fill(0);
            }
            Ok(())
        };

        assert_eq!(generate_from(&mut fill).unwrap(), "32222222");
        assert_eq!(calls, 2);
    }

    #[test]
    fn a_broken_entropy_source_ends_in_an_error_instead_of_a_loop() {
        let mut constant_high = |buffer: &mut [u8]| {
            buffer.fill(255);
            Ok(())
        };
        assert!(generate_from(&mut constant_high).is_err());
        let mut failing = |_: &mut [u8]| Err(EntropyUnavailable);
        assert!(generate_from(&mut failing).is_err());
    }

    #[test]
    fn generated_codes_are_eight_alphabet_symbols_and_differ() {
        let first = generate().unwrap();
        let second = generate().unwrap();
        assert_ne!(first, second);
        for code in [&first, &second] {
            assert_eq!(code.len(), 8);
            assert!(code.bytes().all(|byte| ALPHABET.contains(&byte)));
        }
    }

    #[test]
    fn display_groups_by_four_and_hash_is_the_sha256_of_the_plain_code() {
        assert_eq!(display("WXYZ2345"), "WXYZ-2345");
        assert_eq!(hash("abc").len(), 64);
        assert_eq!(
            hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn typed_codes_are_normalised_and_anything_else_is_refused() {
        for typed in [
            "WXYZ-2345",
            "wxyz-2345",
            "wxyz2345",
            " wx yz-23 45 ",
            "WXYZ2345",
        ] {
            assert_eq!(normalize(typed).as_deref(), Some("WXYZ2345"), "{typed:?}");
        }
        let long = "A".repeat(65);
        for typed in [
            "",
            "WXYZ-234",
            "WXYZ-23456",
            "WXYZ-2O45",
            "WXYZ-2145",
            "WXYZ-2I45",
            "WXYZ-2045",
            "WXYZ_2345",
            "WXYZ\t2345",
            "WXYZ-23\u{0661}5",
            long.as_str(),
        ] {
            assert_eq!(normalize(typed), None, "{typed:?}");
        }
    }
}
