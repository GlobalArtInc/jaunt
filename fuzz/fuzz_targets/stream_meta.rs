#![no_main]

use http::header::{HeaderMap, HeaderName, HeaderValue};
use jaunt_tunnel::{
    HEADER_CLIENT, HEADER_KIND, HEADER_SERVICE, HEADER_SESSION, MAX_CLIENT_ADDRESS_LEN,
    MAX_SESSION_ID_LEN, StreamMeta,
};
use libfuzzer_sys::fuzz_target;

fn headers_from(data: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in data.split(|byte| *byte == b'\n') {
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        if let (Ok(name), Ok(value)) =
            (HeaderName::from_bytes(name), HeaderValue::from_bytes(value))
        {
            headers.append(name, value);
        }
    }
    headers
}

fn headers_of(meta: &StreamMeta) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in [
        (HEADER_SESSION, meta.session().as_str()),
        (HEADER_KIND, meta.kind().as_str()),
        (HEADER_CLIENT, meta.client()),
    ]
    .into_iter()
    .chain(
        meta.service()
            .map(|service| (HEADER_SERVICE, service.as_str())),
    ) {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value).expect("a parsed value is a valid header value"),
        );
    }
    headers
}

fuzz_target!(|data: &[u8]| {
    let Ok(meta) = StreamMeta::from_headers(&headers_from(data)) else {
        return;
    };
    assert!(meta.session().as_str().len() <= MAX_SESSION_ID_LEN);
    assert!(meta.client().len() <= MAX_CLIENT_ADDRESS_LEN);
    let again =
        StreamMeta::from_headers(&headers_of(&meta)).expect("a parsed header set parses again");
    assert_eq!(again, meta);
});
