#![no_main]

use jaunt_proto::AgentTrust;
use jaunt_ssh::UserCaKeys;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(trust) = serde_json::from_slice::<AgentTrust>(data) else {
        return;
    };
    let encoded = serde_json::to_vec(&trust).expect("a parsed trust set encodes");
    let again: AgentTrust = serde_json::from_slice(&encoded).expect("an encoded trust set parses");
    assert_eq!(again, trust);
    if UserCaKeys::from_openssh_lines(&trust.user_ca_keys).is_ok() {
        assert!(!trust.user_ca_keys.is_empty());
    }
});
