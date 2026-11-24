#![no_main]

use jaunt_ssh::parse_node_target;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((port, rest)) = data.split_first_chunk::<4>() else {
        return;
    };
    let port = u32::from_le_bytes(*port);
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let (host, suffix) = text.split_once('\0').unwrap_or((text, "jaunt.test"));
    for port in [port, 22] {
        if let Some(node) = parse_node_target(host, port, suffix) {
            assert_eq!(port, 22);
            assert!(!node.is_empty());
            assert!(!node.contains('.'));
            assert_eq!(node, node.to_ascii_lowercase());
            assert!(host.to_ascii_lowercase().starts_with(&node));
        }
    }
});
