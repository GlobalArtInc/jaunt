#![allow(dead_code)]

#[path = "../support/recorder.rs"]
mod recorder;

pub use recorder::Captured;

pub fn install_recorder() {
    recorder::install_recorder();
}

pub fn audit_events() -> Vec<Captured> {
    recorder::audit_events()
}

use std::net::SocketAddr;
use std::time::Duration;

use jaunt_gate::TlsEntryConfig;
use jaunt_limits::{AddressLimits, DEFAULT_CAPACITY, Rate};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::time::Instant;

pub const DOMAIN: &str = "svc.example.com";

pub const AGENTS: &str = "agents.example.com";

pub const TRAILING: &[u8] = b"\x14\x03\x03\x00\x01\x01early bytes after the hello";

pub const PROXY_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

pub const SINGLE_RECORD: usize = 1 << 14;

pub fn be16(len: usize) -> [u8; 2] {
    u16::try_from(len).unwrap().to_be_bytes()
}

pub fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend(kind.to_be_bytes());
    out.extend(be16(data.len()));
    out.extend(data);
}

pub fn hello_message(server_name: Option<&[u8]>, alpn: &[&[u8]], filler: usize) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(name) = server_name {
        let mut list = vec![0];
        list.extend(be16(name.len()));
        list.extend(name);
        let mut data = be16(list.len()).to_vec();
        data.extend(list);
        extension(&mut extensions, 0x0000, &data);
    }
    extension(&mut extensions, 0x002b, &[2, 3, 4]);
    extension(&mut extensions, 0x000d, &[0, 2, 8, 7]);
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for protocol in alpn {
            list.push(u8::try_from(protocol.len()).unwrap());
            list.extend(*protocol);
        }
        let mut data = be16(list.len()).to_vec();
        data.extend(list);
        extension(&mut extensions, 0x0010, &data);
    }
    let filler: Vec<u8> = (0..filler)
        .map(|at| u8::try_from(at % 251).unwrap())
        .collect();
    extension(&mut extensions, 0x7a7a, &filler);
    let mut body = vec![3, 3];
    body.extend([0x11; 32]);
    body.push(32);
    body.extend([0x22; 32]);
    body.extend([0, 2, 0x13, 0x01, 1, 0]);
    body.extend(be16(extensions.len()));
    body.extend(extensions);
    let mut message = vec![1, 0];
    message.extend(be16(body.len()));
    message.extend(body);
    message
}

pub fn records(message: &[u8], fragment: usize) -> Vec<u8> {
    message
        .chunks(fragment)
        .flat_map(|chunk| [&[22, 3, 1][..], &be16(chunk.len()), chunk].concat())
        .collect()
}

pub fn hello(server_name: &str, alpn: &[&[u8]]) -> Vec<u8> {
    records(
        &hello_message(Some(server_name.as_bytes()), alpn, 16),
        SINGLE_RECORD,
    )
}

pub fn hello_of_size(wire: usize, fragment: usize) -> Vec<u8> {
    let base = hello_message(Some(AGENTS.as_bytes()), &[], 0).len();
    let record_headers = 5 * (wire - 5).div_ceil(fragment + 5);
    let built = records(
        &hello_message(Some(AGENTS.as_bytes()), &[], wire - record_headers - base),
        fragment,
    );
    assert_eq!(built.len(), wire);
    built
}

pub fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

pub fn limits(concurrent: usize) -> AddressLimits {
    AddressLimits {
        rate: Rate::clamped(10_000, 10_000),
        concurrent,
        tracked: DEFAULT_CAPACITY,
    }
}

pub fn config() -> TlsEntryConfig {
    TlsEntryConfig::new(
        vec![AGENTS.to_owned()],
        Some(DOMAIN.to_owned()),
        limits(64),
        limits(64),
    )
}

pub fn proxied(mut config: TlsEntryConfig) -> TlsEntryConfig {
    config.proxy_protocol = true;
    config.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
    config
}

pub fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

pub fn proxy_header(client: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(client) = client else {
        panic!("only TCP4 headers are built here");
    };
    let mut payload = client.ip().octets().to_vec();
    payload.extend([10, 0, 0, 1]);
    payload.extend(client.port().to_be_bytes());
    payload.extend(443_u16.to_be_bytes());
    [
        PROXY_SIGNATURE,
        &[0x21, 0x11],
        &be16(payload.len()),
        &payload,
    ]
    .concat()
}

pub async fn sent(parts: &[&[u8]]) -> (DuplexStream, DuplexStream) {
    let (near, mut far) = duplex(64 * 1024);
    far.write_all(&parts.concat()).await.unwrap();
    (near, far)
}

pub fn refusals() -> Vec<(String, String)> {
    audit_events()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("gate.tls.refused"))
        .map(|event| (event["reason"].clone(), event["suppressed"].clone()))
        .collect()
}

pub async fn read_exactly<R: AsyncRead + Unpin>(stream: &mut R, len: usize) -> Vec<u8> {
    let mut all = vec![0; len];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut all))
        .await
        .expect("the read stalled")
        .unwrap();
    all
}

pub async fn at_end<R: AsyncRead + Unpin>(stream: &mut R) -> bool {
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the read stalled");
    matches!(read, Ok(0))
}
