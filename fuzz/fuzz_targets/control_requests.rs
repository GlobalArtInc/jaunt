#![no_main]

use jaunt_proto::{
    DevicePollRequest, DeviceStartRequest, EnrollRequest, FinishRequest, PollRequest, StartRequest,
};
use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn round_trip<T: Serialize + DeserializeOwned>(data: &[u8]) {
    let Ok(parsed) = serde_json::from_slice::<T>(data) else {
        return;
    };
    let first = serde_json::to_value(&parsed).expect("a parsed request encodes");
    let again: T = serde_json::from_value(first.clone()).expect("an encoded request parses");
    let second: Value = serde_json::to_value(&again).expect("a reparsed request encodes");
    assert_eq!(first, second);
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    match selector % 6 {
        0 => round_trip::<EnrollRequest>(body),
        1 => round_trip::<PollRequest>(body),
        2 => round_trip::<StartRequest>(body),
        3 => round_trip::<FinishRequest>(body),
        4 => round_trip::<DeviceStartRequest>(body),
        _ => round_trip::<DevicePollRequest>(body),
    }
});
