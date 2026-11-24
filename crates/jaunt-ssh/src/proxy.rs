use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const HEADER_LEN: usize = 16;
pub const MAX_PROXY_PAYLOAD: usize = 512;
const COMMAND_LOCAL: u8 = 0x20;
const COMMAND_PROXY: u8 = 0x21;
const FAMILY_TCP4: u8 = 0x11;
const FAMILY_TCP6: u8 = 0x21;
const TCP4_ADDRESSES: usize = 12;
const TCP6_ADDRESSES: usize = 36;
const TLV_HEADER: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxiedAddr {
    pub client: SocketAddr,
    pub local: bool,
}

impl ProxiedAddr {
    pub fn client_or(self, peer: SocketAddr) -> SocketAddr {
        if self.local { peer } else { self.client }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    #[error("the PROXY header ended early")]
    Truncated,
    #[error("the connection does not start with a PROXY v2 signature")]
    Signature,
    #[error("the PROXY header has an unsupported version or command")]
    VersionCommand,
    #[error("the PROXY header carries an unsupported address family")]
    Family,
    #[error("the PROXY header is longer than {MAX_PROXY_PAYLOAD} bytes")]
    Length,
    #[error("the PROXY header address block is malformed")]
    Addresses,
    #[error("the PROXY header carries an unspecified client address or port")]
    UnspecifiedClient,
    #[error("the PROXY header TLV list is malformed")]
    Tlv,
    #[error("bytes follow the PROXY header")]
    TrailingBytes,
    #[error("reading the PROXY header failed: {0:?}")]
    Io(std::io::ErrorKind),
}

pub async fn read_proxy_v2<R: AsyncRead + Unpin>(io: &mut R) -> Result<ProxiedAddr, ProxyError> {
    let mut header = [0u8; HEADER_LEN];
    read_exact(io, &mut header).await?;
    let payload_len = check_header(&header)?;
    let mut payload = vec![0u8; payload_len];
    read_exact(io, &mut payload).await?;
    decode_payload(&header, &payload)
}

pub fn decode_proxy_v2(bytes: &[u8]) -> Result<ProxiedAddr, ProxyError> {
    let (header, payload) = bytes
        .split_first_chunk::<HEADER_LEN>()
        .ok_or(ProxyError::Truncated)?;
    let payload_len = check_header(header)?;
    match payload.len().cmp(&payload_len) {
        std::cmp::Ordering::Less => Err(ProxyError::Truncated),
        std::cmp::Ordering::Greater => Err(ProxyError::TrailingBytes),
        std::cmp::Ordering::Equal => decode_payload(header, payload),
    }
}

async fn read_exact<R: AsyncRead + Unpin>(io: &mut R, buf: &mut [u8]) -> Result<(), ProxyError> {
    match io.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            Err(ProxyError::Truncated)
        }
        Err(error) => Err(ProxyError::Io(error.kind())),
    }
}

fn check_header(header: &[u8; HEADER_LEN]) -> Result<usize, ProxyError> {
    let [signature @ .., command, family, len_hi, len_lo] = header;
    if signature != &SIGNATURE {
        return Err(ProxyError::Signature);
    }
    let payload_len = usize::from(u16::from_be_bytes([*len_hi, *len_lo]));
    if payload_len > MAX_PROXY_PAYLOAD {
        return Err(ProxyError::Length);
    }
    match *command {
        COMMAND_LOCAL => Ok(payload_len),
        COMMAND_PROXY => {
            let needed = address_len(*family)?;
            if payload_len < needed {
                return Err(ProxyError::Addresses);
            }
            Ok(payload_len)
        }
        _ => Err(ProxyError::VersionCommand),
    }
}

fn address_len(family: u8) -> Result<usize, ProxyError> {
    match family {
        FAMILY_TCP4 => Ok(TCP4_ADDRESSES),
        FAMILY_TCP6 => Ok(TCP6_ADDRESSES),
        _ => Err(ProxyError::Family),
    }
}

fn decode_payload(header: &[u8; HEADER_LEN], payload: &[u8]) -> Result<ProxiedAddr, ProxyError> {
    let [.., command, family, _, _] = header;
    if *command == COMMAND_LOCAL {
        return Ok(ProxiedAddr {
            client: SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            local: true,
        });
    }
    let (client, tlvs) = match *family {
        FAMILY_TCP4 => {
            let (addresses, tlvs) = payload
                .split_first_chunk::<TCP4_ADDRESSES>()
                .ok_or(ProxyError::Addresses)?;
            let [a, b, c, d, _, _, _, _, port_hi, port_lo, _, _] = *addresses;
            let ip = Ipv4Addr::new(a, b, c, d);
            (
                SocketAddr::from((ip, u16::from_be_bytes([port_hi, port_lo]))),
                tlvs,
            )
        }
        FAMILY_TCP6 => {
            let (addresses, tlvs) = payload
                .split_first_chunk::<TCP6_ADDRESSES>()
                .ok_or(ProxyError::Addresses)?;
            let (source, rest) = addresses
                .split_first_chunk::<16>()
                .ok_or(ProxyError::Addresses)?;
            let source_port = rest
                .get(16..)
                .and_then(<[u8]>::first_chunk::<2>)
                .ok_or(ProxyError::Addresses)?;
            let ip = Ipv6Addr::from(*source);
            let ip = match ip.to_ipv4_mapped() {
                Some(mapped) => IpAddr::V4(mapped),
                None => IpAddr::V6(ip),
            };
            (
                SocketAddr::from((ip, u16::from_be_bytes(*source_port))),
                tlvs,
            )
        }
        _ => return Err(ProxyError::Family),
    };
    check_tlvs(tlvs)?;
    if client.ip().is_unspecified() || client.port() == 0 {
        return Err(ProxyError::UnspecifiedClient);
    }
    Ok(ProxiedAddr {
        client,
        local: false,
    })
}

fn check_tlvs(mut rest: &[u8]) -> Result<(), ProxyError> {
    while !rest.is_empty() {
        let (tlv_header, after) = rest
            .split_first_chunk::<TLV_HEADER>()
            .ok_or(ProxyError::Tlv)?;
        let [_, len_hi, len_lo] = *tlv_header;
        let value_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        rest = after.get(value_len..).ok_or(ProxyError::Tlv)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::AsyncReadExt;

    use super::{ProxiedAddr, ProxyError, decode_proxy_v2, read_proxy_v2};

    const SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

    fn header(command: u8, family: u8, payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len()).unwrap();
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[command, family]);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn tcp4() -> Vec<u8> {
        let mut payload = vec![203, 0, 113, 7, 10, 0, 0, 1];
        payload.extend_from_slice(&51000u16.to_be_bytes());
        payload.extend_from_slice(&2222u16.to_be_bytes());
        payload
    }

    fn tcp4_from(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut payload = ip.to_vec();
        payload.extend_from_slice(&[10, 0, 0, 1]);
        payload.extend_from_slice(&port.to_be_bytes());
        payload.extend_from_slice(&2222u16.to_be_bytes());
        payload
    }

    fn tcp6_from(ip: &str, port: u16) -> Vec<u8> {
        let mut payload = ip.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec();
        payload.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        payload.extend_from_slice(&port.to_be_bytes());
        payload.extend_from_slice(&2222u16.to_be_bytes());
        payload
    }

    fn tcp6() -> Vec<u8> {
        let mut payload = "2001:db8::7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec();
        payload.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        payload.extend_from_slice(&51000u16.to_be_bytes());
        payload.extend_from_slice(&2222u16.to_be_bytes());
        payload
    }

    fn proxied(client: &str) -> Result<ProxiedAddr, ProxyError> {
        Ok(ProxiedAddr {
            client: client.parse().unwrap(),
            local: false,
        })
    }

    fn local() -> Result<ProxiedAddr, ProxyError> {
        Ok(ProxiedAddr {
            client: "0.0.0.0:0".parse().unwrap(),
            local: true,
        })
    }

    #[test]
    fn headers_decode_by_the_v2_rules() {
        let with_tlvs = {
            let mut payload = tcp4();
            payload.extend_from_slice(&[0x04, 0x00, 0x02, 0xaa, 0xbb, 0x01, 0x00, 0x00]);
            payload
        };
        let dangling_tlv = {
            let mut payload = tcp4();
            payload.extend_from_slice(&[0x04, 0x00, 0x05, 0xaa]);
            payload
        };
        let short_tlv = {
            let mut payload = tcp4();
            payload.extend_from_slice(&[0x04, 0x00]);
            payload
        };
        let mut v1 = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 2222\r\n".to_vec();
        v1.resize(40, 0);
        let mut bad_signature = header(0x21, 0x11, &tcp4());
        bad_signature[11] = b'X';
        let mut trailing = header(0x21, 0x11, &tcp4());
        trailing.push(b'S');
        let oversized = header(0x21, 0x11, &vec![0; 513]);
        let largest = {
            let mut payload = tcp4();
            payload.extend_from_slice(&[0x04, 0x01, 0xf1]);
            payload.resize(512, 0);
            header(0x21, 0x11, &payload)
        };
        let full_header = header(0x21, 0x11, &tcp4());
        let cases: Vec<(&str, Vec<u8>, Result<ProxiedAddr, ProxyError>)> = vec![
            (
                "TCP4",
                header(0x21, 0x11, &tcp4()),
                proxied("203.0.113.7:51000"),
            ),
            (
                "TCP6",
                header(0x21, 0x21, &tcp6()),
                proxied("[2001:db8::7]:51000"),
            ),
            (
                "TCP6 carrying a mapped IPv4 client",
                header(0x21, 0x21, &tcp6_from("::ffff:203.0.113.7", 51000)),
                proxied("203.0.113.7:51000"),
            ),
            (
                "TCP4 unspecified client",
                header(0x21, 0x11, &tcp4_from([0, 0, 0, 0], 51000)),
                Err(ProxyError::UnspecifiedClient),
            ),
            (
                "TCP4 client port 0",
                header(0x21, 0x11, &tcp4_from([203, 0, 113, 7], 0)),
                Err(ProxyError::UnspecifiedClient),
            ),
            (
                "TCP6 unspecified client",
                header(0x21, 0x21, &tcp6_from("::", 51000)),
                Err(ProxyError::UnspecifiedClient),
            ),
            (
                "TCP6 mapped unspecified client",
                header(0x21, 0x21, &tcp6_from("::ffff:0.0.0.0", 51000)),
                Err(ProxyError::UnspecifiedClient),
            ),
            (
                "TCP6 client port 0",
                header(0x21, 0x21, &tcp6_from("2001:db8::7", 0)),
                Err(ProxyError::UnspecifiedClient),
            ),
            (
                "TCP4 with TLVs",
                header(0x21, 0x11, &with_tlvs),
                proxied("203.0.113.7:51000"),
            ),
            ("largest allowed", largest, proxied("203.0.113.7:51000")),
            ("LOCAL UNSPEC", header(0x20, 0x00, &[]), local()),
            ("LOCAL with addresses", header(0x20, 0x11, &tcp4()), local()),
            (
                "PROXY UNSPEC",
                header(0x21, 0x00, &[]),
                Err(ProxyError::Family),
            ),
            (
                "PROXY UDP4",
                header(0x21, 0x12, &tcp4()),
                Err(ProxyError::Family),
            ),
            (
                "PROXY UNIX",
                header(0x21, 0x31, &[0; 216]),
                Err(ProxyError::Family),
            ),
            (
                "PROXY TCP6 short",
                header(0x21, 0x21, &tcp4()),
                Err(ProxyError::Addresses),
            ),
            (
                "PROXY TCP4 short",
                header(0x21, 0x11, &[0; 11]),
                Err(ProxyError::Addresses),
            ),
            (
                "version 1 byte",
                header(0x11, 0x11, &tcp4()),
                Err(ProxyError::VersionCommand),
            ),
            (
                "unknown command",
                header(0x22, 0x11, &tcp4()),
                Err(ProxyError::VersionCommand),
            ),
            ("text v1", v1, Err(ProxyError::Signature)),
            ("bad signature", bad_signature, Err(ProxyError::Signature)),
            (
                "SSH banner",
                b"SSH-2.0-OpenSSH_10.0\r\n".to_vec(),
                Err(ProxyError::Signature),
            ),
            ("oversized", oversized, Err(ProxyError::Length)),
            (
                "dangling TLV",
                header(0x21, 0x11, &dangling_tlv),
                Err(ProxyError::Tlv),
            ),
            (
                "short TLV header",
                header(0x21, 0x11, &short_tlv),
                Err(ProxyError::Tlv),
            ),
            (
                "truncated header",
                full_header[..10].to_vec(),
                Err(ProxyError::Truncated),
            ),
            (
                "truncated payload",
                full_header[..20].to_vec(),
                Err(ProxyError::Truncated),
            ),
            ("empty", Vec::new(), Err(ProxyError::Truncated)),
            ("trailing byte", trailing, Err(ProxyError::TrailingBytes)),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(decode_proxy_v2(&bytes), expected, "{name}");
            if expected != Err(ProxyError::TrailingBytes) {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap();
                let streamed = runtime.block_on(read_proxy_v2(&mut bytes.as_slice()));
                assert_eq!(streamed, expected, "{name} (streamed)");
            }
        }
    }

    #[tokio::test]
    async fn the_reader_stops_exactly_after_the_header() {
        let mut stream = header(0x21, 0x11, &tcp4());
        stream.extend_from_slice(b"SSH-2.0-OpenSSH_10.0\r\n");
        let mut reader = stream.as_slice();
        let addr = read_proxy_v2(&mut reader).await.unwrap();
        assert_eq!(
            addr.client,
            "203.0.113.7:51000".parse::<SocketAddr>().unwrap()
        );
        let mut rest = String::new();
        reader.read_to_string(&mut rest).await.unwrap();
        assert_eq!(rest, "SSH-2.0-OpenSSH_10.0\r\n");
    }

    #[tokio::test]
    async fn a_stalled_sender_is_cut_by_the_caller_deadline() {
        let (mut reader, mut writer) = tokio::io::duplex(64);
        let partial = header(0x21, 0x11, &tcp4());
        tokio::io::AsyncWriteExt::write_all(&mut writer, &partial[..20])
            .await
            .unwrap();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            read_proxy_v2(&mut reader),
        )
        .await;
        assert!(outcome.is_err());
    }

    #[test]
    fn local_uses_the_tcp_peer() {
        let peer: SocketAddr = "192.0.2.10:40000".parse().unwrap();
        let local = decode_proxy_v2(&header(0x20, 0x00, &[])).unwrap();
        let remote = decode_proxy_v2(&header(0x21, 0x11, &tcp4())).unwrap();
        assert_eq!(local.client_or(peer), peer);
        assert_eq!(
            remote.client_or(peer),
            "203.0.113.7:51000".parse::<SocketAddr>().unwrap()
        );
    }
}
