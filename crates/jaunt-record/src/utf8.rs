use std::fmt;

const REPLACEMENT: char = '\u{FFFD}';

#[derive(Default)]
pub(crate) struct Utf8Stream {
    carry: Vec<u8>,
}

impl fmt::Debug for Utf8Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Utf8Stream")
            .field("carried_bytes", &self.carry.len())
            .finish()
    }
}

impl Utf8Stream {
    pub(crate) fn decode(&mut self, data: &[u8], flush: bool) -> String {
        let mut buffer = std::mem::take(&mut self.carry);
        buffer.extend_from_slice(data);
        let mut out = String::with_capacity(buffer.len());
        let mut rest: &[u8] = &buffer;
        loop {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    out.push_str(valid);
                    break;
                }
                Err(error) => {
                    let (valid, tail) = rest.split_at(error.valid_up_to());
                    out.push_str(&String::from_utf8_lossy(valid));
                    match error.error_len() {
                        Some(invalid) => {
                            out.push(REPLACEMENT);
                            rest = &tail[invalid..];
                        }
                        None => {
                            if flush {
                                out.push(REPLACEMENT);
                            } else {
                                self.carry.extend_from_slice(tail);
                            }
                            break;
                        }
                    }
                }
            }
        }
        out
    }

    #[cfg(test)]
    pub(crate) fn carried(&self) -> usize {
        self.carry.len()
    }
}

pub(crate) fn split_at_char_boundary(text: &str, max_bytes: usize) -> (&str, &str) {
    if text.len() <= max_bytes {
        return (text, "");
    }
    let mut at = max_bytes;
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    text.split_at(at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_shows_only_the_carried_count() {
        let mut stream = Utf8Stream::default();
        assert_eq!(stream.decode(&[0xe2, 0x82], false), "");
        let shown = format!("{stream:?}");
        assert!(shown.contains("carried_bytes: 2"));
        assert!(!shown.contains("226") && !shown.contains("130"));
    }
}
