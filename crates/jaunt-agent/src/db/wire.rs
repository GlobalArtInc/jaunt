use bytes::{BufMut, BytesMut};

pub const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];
pub const AUTHENTICATION_OK: [u8; 9] = [b'R', 0, 0, 0, 8, 0, 0, 0, 0];
pub const TERMINATE: [u8; 5] = [b'X', 0, 0, 0, 4];
pub const NO_ENCRYPTION: u8 = b'N';
pub const SSL_ACCEPTED: u8 = b'S';

const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
const FATAL: &str = "FATAL";

pub const ACCESS_DENIED: (&str, &str) = ("28000", "access denied");
pub const UNAVAILABLE: (&str, &str) = ("08006", "the Jaunt service is not available");
pub const PASSWORD_REQUESTED: (&str, &str) = (
    "28000",
    "the database asked for a password: configure the cert authentication method for Jaunt",
);
pub const DATABASE_REFUSED: &str = "the database refused the session";
pub const FUNCTION_CALLS: (&str, &str) = (
    "0A000",
    "fast-path function calls are not supported through Jaunt",
);
pub const PROTOCOL_VIOLATION: &str = "08P01";
pub const INVALID_STARTUP: &str = "the startup packet is not valid PostgreSQL protocol 3";

pub fn error_response(code: &str, message: &str) -> Vec<u8> {
    let mut body = BytesMut::new();
    for (field, value) in [(b'S', FATAL), (b'V', FATAL), (b'C', code), (b'M', message)] {
        body.put_u8(field);
        body.extend(value.bytes().filter(|byte| *byte != 0));
        body.put_u8(0);
    }
    body.put_u8(0);
    framed(b'E', &body)
}

pub fn cancel_request(process_id: i32, secret_key: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(12 + secret_key.len());
    out.put_u32(u32::try_from(12 + secret_key.len()).unwrap_or(u32::MAX));
    out.put_u32(CANCEL_REQUEST_CODE);
    out.put_i32(process_id);
    out.put_slice(secret_key);
    out.to_vec()
}

pub fn is_sqlstate(code: &str) -> bool {
    code.len() == 5
        && code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
}

fn framed(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.put_u8(tag);
    out.put_u32(u32::try_from(body.len() + 4).unwrap_or(u32::MAX));
    out.put_slice(body);
    out.to_vec()
}

#[cfg(test)]
mod tests {
    use jaunt_pgwire::{BackendDecoder, BackendMessage, Event, Limits};

    use super::{AUTHENTICATION_OK, cancel_request, error_response, is_sqlstate};

    fn decode(bytes: &[u8]) -> Vec<BackendMessage> {
        let mut decoder = BackendDecoder::new(Limits::default()).unwrap();
        decoder.push(bytes).unwrap();
        let mut messages = Vec::new();
        while let Some(Event::Frame(frame)) = decoder.next_event().unwrap() {
            messages.push(frame.into_message());
        }
        messages
    }

    #[test]
    fn the_messages_the_agent_writes_decode_as_postgresql_messages() {
        let mut bytes = AUTHENTICATION_OK.to_vec();
        bytes.extend(error_response("28000", "access\0 denied"));
        let messages = decode(&bytes);
        assert!(matches!(&messages[0], BackendMessage::Authentication(auth) if auth.is_ok()));
        let BackendMessage::ErrorResponse(notice) = &messages[1] else {
            panic!("expected an error response, got {:?}", messages[1]);
        };
        assert_eq!(
            (notice.severity.as_str(), notice.code.as_str()),
            ("FATAL", "28000")
        );
        assert_eq!(notice.message, "access denied");
    }

    #[test]
    fn a_cancel_request_carries_the_pair_and_its_length() {
        assert_eq!(
            cancel_request(7, &[1, 2, 3, 4]),
            [0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 7, 1, 2, 3, 4]
        );
        assert_eq!(cancel_request(7, &[9; 32]).len(), 44);
    }

    #[test]
    fn only_five_character_codes_are_sqlstates() {
        for (code, valid) in [
            ("3D000", true),
            ("08006", true),
            ("3d000", false),
            ("3D00", false),
            ("3D0000", false),
            ("3D\"00", false),
        ] {
            assert_eq!(is_sqlstate(code), valid, "{code}");
        }
    }
}
