const SSH_PORT: u32 = 22;
const MAX_LABEL_LEN: usize = 63;

pub fn parse_node_target(host: &str, port: u32, suffix: &str) -> Option<String> {
    if port != SSH_PORT || suffix.is_empty() {
        return None;
    }
    let lowered = host.to_ascii_lowercase();
    let name = lowered.strip_suffix('.').unwrap_or(&lowered);
    let label = name.strip_suffix(suffix)?.strip_suffix('.')?;
    is_dns_label(label).then(|| label.to_owned())
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_LABEL_LEN
        && edge(*first)
        && edge(*last)
        && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::{is_dns_label, parse_node_target};

    const SUFFIX: &str = "jaunt.example.com";

    #[test]
    fn dns_labels_follow_the_lowercase_rule() {
        let long = "a".repeat(63);
        let too_long = "a".repeat(64);
        for (label, ok) in [
            ("web-01", true),
            ("a", true),
            ("0a", true),
            (long.as_str(), true),
            (too_long.as_str(), false),
            ("", false),
            ("-web", false),
            ("web-", false),
            ("Web", false),
            ("we_b", false),
            ("web.01", false),
        ] {
            assert_eq!(is_dns_label(label), ok, "{label:?}");
        }
    }

    #[test]
    fn only_a_node_label_under_the_suffix_on_port_22_is_a_target() {
        let long = format!("{}.{SUFFIX}", "a".repeat(63));
        let too_long = format!("{}.{SUFFIX}", "a".repeat(64));
        for (host, port, expected) in [
            ("node1.jaunt.example.com", 22, Some("node1")),
            ("NODE1.Jaunt.Example.COM", 22, Some("node1")),
            ("node1.jaunt.example.com.", 22, Some("node1")),
            ("xn--bcher-kva.jaunt.example.com", 22, Some("xn--bcher-kva")),
            (
                long.as_str(),
                22,
                Some(long.split('.').next().unwrap_or("")),
            ),
            (too_long.as_str(), 22, None),
            ("node1.jaunt.example.com..", 22, None),
            ("node1.jaunt.example.com", 2222, None),
            ("node1.jaunt.example.com", 0, None),
            ("node1.jaunt.example.com", 22 + 65536, None),
            ("node1.other.example.com", 22, None),
            ("node1.jaunt.example.com.evil.test", 22, None),
            ("node1jaunt.example.com", 22, None),
            ("jaunt.example.com", 22, None),
            (".jaunt.example.com", 22, None),
            ("a.b.jaunt.example.com", 22, None),
            ("-node.jaunt.example.com", 22, None),
            ("bücher.jaunt.example.com", 22, None),
            ("10.0.0.1", 22, None),
            ("[::1]", 22, None),
            ("deploy@node1.jaunt.example.com", 22, None),
            ("node1.jaunt.example.com:22", 22, None),
            ("node 1.jaunt.example.com", 22, None),
            ("", 22, None),
        ] {
            assert_eq!(
                parse_node_target(host, port, SUFFIX).as_deref(),
                expected,
                "{host:?}:{port}"
            );
        }
    }

    #[test]
    fn an_empty_suffix_matches_nothing() {
        assert_eq!(parse_node_target("node1.", 22, ""), None);
        assert_eq!(parse_node_target("node1", 22, ""), None);
    }
}
