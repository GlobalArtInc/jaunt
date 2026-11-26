#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plus {
    Literal,
    Space,
}

pub(crate) fn percent_decode(input: &[u8], plus: Plus) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut rest = input;
    while let Some((&byte, tail)) = rest.split_first() {
        match byte {
            b'%' => {
                let [high, low, after @ ..] = tail else {
                    return None;
                };
                out.push((hex_value(*high)? << 4) | hex_value(*low)?);
                rest = after;
            }
            b'+' if plus == Plus::Space => {
                out.push(b' ');
                rest = tail;
            }
            other => {
                out.push(other);
                rest = tail;
            }
        }
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_a_go_url_parser() {
        for (input, plus, expected) in [
            ("a%2Fb", Plus::Literal, Some("a/b")),
            ("a%2fb", Plus::Literal, Some("a/b")),
            ("a+b", Plus::Literal, Some("a+b")),
            ("a+b", Plus::Space, Some("a b")),
            ("%", Plus::Literal, None),
            ("%4", Plus::Literal, None),
            ("%zz", Plus::Literal, None),
            ("%%41", Plus::Literal, None),
            ("", Plus::Literal, Some("")),
        ] {
            let decoded = percent_decode(input.as_bytes(), plus);
            assert_eq!(
                decoded.as_deref(),
                expected.map(str::as_bytes),
                "input {input:?}"
            );
        }
    }
}
