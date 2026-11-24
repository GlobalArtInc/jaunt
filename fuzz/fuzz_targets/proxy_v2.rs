#![no_main]

use jaunt_ssh::{MAX_PROXY_PAYLOAD, decode_proxy_v2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(proxied) = decode_proxy_v2(data) {
        assert!(data.len() <= 16 + MAX_PROXY_PAYLOAD);
        if !proxied.local {
            assert_ne!(proxied.client.port(), 0);
            assert!(!proxied.client.ip().is_unspecified());
        }
    }
});
