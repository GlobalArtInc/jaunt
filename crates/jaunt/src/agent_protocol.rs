use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use ssh_key::public::KeyData;
use ssh_key::{PublicKey, Signature};

const AGENT_FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const NO_FLAGS: u32 = 0;
const MAX_MESSAGE_BYTES: usize = 256 * 1024;
const MAX_IDENTITIES: u32 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum AgentProtocolError {
    #[error("cannot connect to ssh-agent: {0}")]
    Connect(io::Error),
    #[error("cannot talk to ssh-agent: {0}")]
    Io(io::Error),
    #[error("ssh-agent did not answer in time")]
    TimedOut,
    #[error("ssh-agent refused the request")]
    Refused,
    #[error("ssh-agent sent an answer that cannot be understood")]
    Malformed,
    #[error("cannot encode the key for ssh-agent")]
    Encode,
}

#[derive(Debug, Clone)]
pub struct AgentClient {
    socket: PathBuf,
    timeout: Duration,
}

impl AgentClient {
    pub fn new(socket: PathBuf, timeout: Duration) -> AgentClient {
        AgentClient { socket, timeout }
    }

    pub fn holds(&self, key: &KeyData) -> Result<bool, AgentProtocolError> {
        let wanted = key_blob(key)?;
        Ok(self.identities()?.contains(&wanted))
    }

    pub fn identities(&self) -> Result<Vec<Vec<u8>>, AgentProtocolError> {
        let answer = self.exchange(vec![REQUEST_IDENTITIES])?;
        let mut reader = Fields::new(&answer);
        match reader.byte()? {
            IDENTITIES_ANSWER => {}
            AGENT_FAILURE => return Err(AgentProtocolError::Refused),
            _ => return Err(AgentProtocolError::Malformed),
        }
        let count = reader.u32()?;
        if count > MAX_IDENTITIES {
            return Err(AgentProtocolError::Malformed);
        }
        let mut blobs = Vec::new();
        for _ in 0..count {
            blobs.push(reader.string()?.to_vec());
            reader.string()?;
        }
        reader.finish()?;
        Ok(blobs)
    }

    pub fn sign(&self, key: &KeyData, data: &[u8]) -> Result<Signature, AgentProtocolError> {
        let blob = key_blob(key)?;
        let mut request = vec![SIGN_REQUEST];
        put_string(&mut request, &blob)?;
        put_string(&mut request, data)?;
        request.extend_from_slice(&NO_FLAGS.to_be_bytes());
        let answer = self.exchange(request)?;
        let mut reader = Fields::new(&answer);
        match reader.byte()? {
            SIGN_RESPONSE => {}
            AGENT_FAILURE => return Err(AgentProtocolError::Refused),
            _ => return Err(AgentProtocolError::Malformed),
        }
        let encoded = reader.string()?;
        reader.finish()?;
        let mut inner = Fields::new(encoded);
        inner.string()?;
        inner.string()?;
        inner.finish()?;
        let signature = Signature::try_from(encoded).map_err(|_| AgentProtocolError::Malformed)?;
        if signature.algorithm() != key.algorithm() {
            return Err(AgentProtocolError::Malformed);
        }
        Ok(signature)
    }

    fn exchange(&self, payload: Vec<u8>) -> Result<Vec<u8>, AgentProtocolError> {
        let (results, inbox) = mpsc::channel();
        let socket = self.socket.clone();
        let timeout = self.timeout;
        thread::Builder::new()
            .name("jaunt-ssh-agent".to_owned())
            .spawn(move || drop(results.send(talk(&socket, &payload, timeout))))
            .map_err(AgentProtocolError::Io)?;
        match inbox.recv_timeout(self.timeout) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) => Err(AgentProtocolError::TimedOut),
            Err(RecvTimeoutError::Disconnected) => Err(AgentProtocolError::Io(io::Error::other(
                "the ssh-agent exchange ended without an answer",
            ))),
        }
    }
}

fn talk(socket: &Path, payload: &[u8], timeout: Duration) -> Result<Vec<u8>, AgentProtocolError> {
    let mut stream = UnixStream::connect(socket).map_err(AgentProtocolError::Connect)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(AgentProtocolError::Io)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(AgentProtocolError::Io)?;
    let length = u32::try_from(payload.len()).map_err(|_| AgentProtocolError::Encode)?;
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    stream.write_all(&frame).map_err(io_failure)?;
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).map_err(io_failure)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| AgentProtocolError::Malformed)?;
    if length == 0 || length > MAX_MESSAGE_BYTES {
        return Err(AgentProtocolError::Malformed);
    }
    let mut answer = vec![0_u8; length];
    stream.read_exact(&mut answer).map_err(io_failure)?;
    Ok(answer)
}

fn io_failure(err: io::Error) -> AgentProtocolError {
    match err.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => AgentProtocolError::TimedOut,
        _ => AgentProtocolError::Io(err),
    }
}

fn key_blob(key: &KeyData) -> Result<Vec<u8>, AgentProtocolError> {
    PublicKey::from(key.clone())
        .to_bytes()
        .map_err(|_| AgentProtocolError::Encode)
}

fn put_string(out: &mut Vec<u8>, value: &[u8]) -> Result<(), AgentProtocolError> {
    let length = u32::try_from(value.len()).map_err(|_| AgentProtocolError::Encode)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    fn new(bytes: &'a [u8]) -> Fields<'a> {
        Fields { rest: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], AgentProtocolError> {
        if count > self.rest.len() {
            return Err(AgentProtocolError::Malformed);
        }
        let (taken, rest) = self.rest.split_at(count);
        self.rest = rest;
        Ok(taken)
    }

    fn byte(&mut self) -> Result<u8, AgentProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, AgentProtocolError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8], AgentProtocolError> {
        let length = usize::try_from(self.u32()?).map_err(|_| AgentProtocolError::Malformed)?;
        self.take(length)
    }

    fn finish(&self) -> Result<(), AgentProtocolError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(AgentProtocolError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature, SigningKey};

    use super::{AgentClient, AgentProtocolError, Fields, put_string};

    fn serve_once(answer: Vec<u8>) -> (tempfile::TempDir, PathBuf, Receiver<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (requests, received) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut length = [0_u8; 4];
            stream.read_exact(&mut length).unwrap();
            let mut request = vec![0_u8; usize::try_from(u32::from_be_bytes(length)).unwrap()];
            stream.read_exact(&mut request).unwrap();
            requests.send(request).unwrap();
            stream.write_all(&answer).unwrap();
        });
        (dir, socket, received)
    }

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut frame = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    fn raw_sign<S: SigningKey>(key: &S, data: &[u8]) -> Signature {
        key.try_sign(data).unwrap()
    }

    fn sign_response(
        algorithm: &[u8],
        raw: &[u8],
        inner_tail: &[u8],
        outer_tail: &[u8],
    ) -> Vec<u8> {
        let mut blob = Vec::new();
        put_string(&mut blob, algorithm).unwrap();
        put_string(&mut blob, raw).unwrap();
        blob.extend_from_slice(inner_tail);
        let mut payload = vec![14];
        put_string(&mut payload, &blob).unwrap();
        payload.extend_from_slice(outer_tail);
        framed(&payload)
    }

    #[test]
    fn the_sign_request_carries_the_key_blob_the_data_and_no_flags() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let signature = raw_sign(&key, b"data");
        let answer = sign_response(b"ssh-ed25519", signature.as_bytes(), b"", b"");
        let (_dir, socket, requests) = serve_once(answer);

        let signed = AgentClient::new(socket, Duration::from_secs(5))
            .sign(key.public_key().key_data(), b"data")
            .unwrap();

        assert_eq!(signed, signature);
        let mut expected = vec![13];
        let blob = PublicKey::from(key.public_key().key_data().clone())
            .to_bytes()
            .unwrap();
        put_string(&mut expected, &blob).unwrap();
        put_string(&mut expected, b"data").unwrap();
        expected.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            requests.recv_timeout(Duration::from_secs(5)).unwrap(),
            expected
        );
    }

    #[test]
    fn answers_that_break_the_framing_or_the_key_type_are_refused() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let raw = raw_sign(&key, b"data").as_bytes().to_vec();
        let mut too_many = vec![12];
        too_many.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut listed = vec![12];
        listed.extend_from_slice(&1_u32.to_be_bytes());
        put_string(
            &mut listed,
            &PublicKey::from(key.public_key().key_data().clone())
                .to_bytes()
                .unwrap(),
        )
        .unwrap();
        put_string(&mut listed, b"comment").unwrap();
        listed.push(0);
        let identities_with_trailing_byte = framed(&listed);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (framed(&[5]), "failure"),
            (framed(&[99]), "unknown type"),
            (
                sign_response(b"ssh-ed25519", &raw, b"", b"\0"),
                "trailing bytes after the blob",
            ),
            (
                sign_response(b"ssh-ed25519", &raw, b"\0", b""),
                "trailing bytes inside the blob",
            ),
            (
                sign_response(b"rsa-sha2-256", &raw, b"", b""),
                "another key type",
            ),
            (framed(&too_many), "identity count"),
            (
                identities_with_trailing_byte,
                "identity list with a trailing byte",
            ),
            (u32::MAX.to_be_bytes().to_vec(), "oversized frame"),
            (0_u32.to_be_bytes().to_vec(), "empty frame"),
            (vec![0, 0], "short length"),
        ];
        for (answer, case) in cases {
            let (_dir, socket, _requests) = serve_once(answer);
            let client = AgentClient::new(socket, Duration::from_secs(5));
            let outcome = if case.starts_with("identity") {
                client.identities().map(drop)
            } else {
                client.sign(key.public_key().key_data(), b"data").map(drop)
            };
            let expected_refusal = case == "failure";
            match outcome {
                Err(AgentProtocolError::Refused) if expected_refusal => {}
                Err(AgentProtocolError::Malformed)
                    if !expected_refusal && case != "short length" => {}
                Err(AgentProtocolError::Io(_)) if case == "short length" => {}
                other => panic!("{case}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_silent_agent_times_out_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let started = Instant::now();
        let outcome = AgentClient::new(socket, Duration::from_millis(200)).identities();
        assert!(
            matches!(outcome, Err(AgentProtocolError::TimedOut)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
    }

    #[test]
    fn fields_read_ssh_strings_and_refuse_short_input() {
        let mut bytes = Vec::new();
        put_string(&mut bytes, b"abc").unwrap();
        let mut reader = Fields::new(&bytes);
        assert_eq!(reader.string().unwrap(), b"abc");
        assert!(reader.finish().is_ok());
        let mut short = Fields::new(&[0, 0, 0, 9, 1]);
        assert!(short.string().is_err());
    }
}
