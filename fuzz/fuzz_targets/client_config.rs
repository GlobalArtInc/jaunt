#![no_main]

use jaunt_proto::{ClientConfig, NodeList};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(data: &[u8]) {
    let Ok(parsed) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let encoded = serde_json::to_vec(&parsed).expect("a parsed value encodes");
    let again: T = serde_json::from_slice(&encoded).expect("an encoded value parses");
    assert_eq!(again, parsed);
}

fuzz_target!(|data: &[u8]| {
    round_trip::<ClientConfig>(data);
    round_trip::<NodeList>(data);
});
