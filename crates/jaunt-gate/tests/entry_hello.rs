mod entry_support;

use std::time::Duration;

use entry_support::*;
use jaunt_gate::{
    ALPN_SSH, HelloError, MAX_CLIENT_HELLO_BYTES, Replay, capture_client_hello, parse_client_hello,
};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
use tokio::time::{Instant, sleep};

fn sizes() -> Vec<usize> {
    let smallest = 5 + hello_message(Some(AGENTS.as_bytes()), &[], 0).len();
    let span = u64::try_from(MAX_CLIENT_HELLO_BYTES - smallest + 1).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut sizes = vec![smallest, MAX_CLIENT_HELLO_BYTES];
    for _ in 0..24 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        sizes.push(smallest + usize::try_from(state % span).unwrap());
    }
    sizes
}

async fn replayed(captured: Vec<u8>, rest: DuplexStream, expected: &[u8]) {
    let mut replay = Replay::new(captured, rest);
    assert_eq!(read_exactly(&mut replay, expected.len()).await, expected);
    assert!(at_end(&mut replay).await);
}

#[tokio::test(start_paused = true)]
async fn hellos_of_any_size_up_to_the_limit_are_captured_and_replayed_byte_for_byte() {
    for size in sizes() {
        let hello = hello_of_size(size, SINGLE_RECORD);
        let (mut near, mut far) = duplex(64 * 1024);
        far.write_all(&[hello.as_slice(), TRAILING].concat())
            .await
            .unwrap();
        far.shutdown().await.unwrap();
        let captured = capture_client_hello(&mut near, deadline()).await.unwrap();
        assert_eq!(captured.bytes(), hello.as_slice(), "{size}");
        assert_eq!(captured.info().server_name(), Some(AGENTS), "{size}");
        replayed(
            captured.into_parts().0,
            near,
            &[hello.as_slice(), TRAILING].concat(),
        )
        .await;
    }
}

#[tokio::test(start_paused = true)]
async fn a_hello_arriving_one_byte_at_a_time_in_many_records_keeps_the_bytes_after_it() {
    for fragment in [SINGLE_RECORD, 100, 1] {
        let hello = records(
            &hello_message(Some(DOMAIN.as_bytes()), &[ALPN_SSH], 64),
            fragment,
        );
        let sent = [hello.as_slice(), TRAILING].concat();
        let (mut near, mut far) = duplex(1);
        let writer = tokio::spawn(async move {
            far.write_all(&sent).await.unwrap();
            far.shutdown().await.unwrap();
        });
        let captured = capture_client_hello(&mut near, deadline()).await.unwrap();
        assert_eq!(captured.bytes(), hello.as_slice(), "{fragment}");
        assert!(captured.info().offers_ssh() && !captured.info().offers_svc());
        replayed(
            captured.into_parts().0,
            near,
            &[hello.as_slice(), TRAILING].concat(),
        )
        .await;
        writer.await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn sixteen_kib_is_the_largest_hello_and_the_byte_after_it_is_never_read() {
    assert_eq!(MAX_CLIENT_HELLO_BYTES, 16 * 1024);
    for fragment in [SINGLE_RECORD, 10_000] {
        let largest = hello_of_size(MAX_CLIENT_HELLO_BYTES, fragment);
        assert_eq!(
            parse_client_hello(&largest).unwrap().bytes().len(),
            MAX_CLIENT_HELLO_BYTES
        );
        let over = hello_of_size(MAX_CLIENT_HELLO_BYTES + 1, fragment);
        assert_eq!(parse_client_hello(&over), Err(HelloError::TooLarge));
    }
    let over = hello_of_size(MAX_CLIENT_HELLO_BYTES + 1, SINGLE_RECORD);
    let (mut near, mut far) = duplex(64);
    far.write_all(&over[..5]).await.unwrap();
    assert_eq!(
        capture_client_hello(&mut near, deadline()).await,
        Err(HelloError::TooLarge)
    );
}

#[tokio::test(start_paused = true)]
async fn a_silent_or_trickling_client_is_cut_at_the_handshake_deadline() {
    let (mut near, _far) = duplex(64);
    let start = Instant::now();
    assert_eq!(
        capture_client_hello(&mut near, start + Duration::from_secs(10)).await,
        Err(HelloError::Timeout)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(10));

    let (mut near, mut far) = duplex(64);
    let trickle = tokio::spawn(async move {
        for byte in hello(AGENTS, &[]) {
            if far.write_all(&[byte]).await.is_err() {
                return;
            }
            sleep(Duration::from_secs(1)).await;
        }
    });
    let start = Instant::now();
    assert_eq!(
        capture_client_hello(&mut near, start + Duration::from_secs(10)).await,
        Err(HelloError::Timeout)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(10));
    drop(near);
    trickle.await.unwrap();
}

#[tokio::test]
async fn anything_but_a_well_formed_client_hello_is_refused() {
    let message = hello_message(Some(AGENTS.as_bytes()), &[], 0);
    let without_signatures = {
        let mut bytes = records(&message, SINGLE_RECORD);
        let at = bytes
            .windows(6)
            .position(|window| window == [0, 0x0d, 0, 4, 0, 2])
            .unwrap();
        bytes[at + 1] = 0x7b;
        bytes
    };
    let server_hello = {
        let mut changed = message.clone();
        changed[0] = 2;
        records(&changed, SINGLE_RECORD)
    };
    let two_messages = records(
        &[message.as_slice(), &[20, 0, 0, 0]].concat(),
        SINGLE_RECORD,
    );
    let non_ascii = records(
        &hello_message(Some("agënts.example.com".as_bytes()), &[], 0),
        SINGLE_RECORD,
    );
    let mut wrong_version = records(&message, SINGLE_RECORD);
    wrong_version[1] = 2;
    let cases: Vec<(&str, Vec<u8>, HelloError)> = vec![
        (
            "http",
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec(),
            HelloError::Malformed,
        ),
        (
            "proxy header",
            PROXY_SIGNATURE.to_vec(),
            HelloError::Malformed,
        ),
        (
            "alert record",
            vec![21, 3, 3, 0, 2, 2, 40],
            HelloError::Malformed,
        ),
        ("empty record", vec![22, 3, 1, 0, 0], HelloError::Malformed),
        (
            "oversized record",
            vec![22, 3, 1, 0x40, 0x01],
            HelloError::Malformed,
        ),
        ("wrong record version", wrong_version, HelloError::Malformed),
        ("server hello", server_hello, HelloError::Malformed),
        (
            "no signature algorithms",
            without_signatures,
            HelloError::Malformed,
        ),
        (
            "a message after the hello",
            two_messages,
            HelloError::Malformed,
        ),
        ("non ascii server name", non_ascii, HelloError::Malformed),
        (
            "random body",
            [&[22, 3, 1, 0, 8][..], &[0x5a; 8]].concat(),
            HelloError::Malformed,
        ),
        (
            "cut body",
            records(&message, SINGLE_RECORD)[..40].to_vec(),
            HelloError::Truncated,
        ),
        ("empty", Vec::new(), HelloError::Truncated),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(parse_client_hello(&bytes), Err(expected), "{name}");
    }
    let (mut near, far) = duplex(64);
    drop(far);
    assert_eq!(
        capture_client_hello(&mut near, deadline()).await,
        Err(HelloError::Truncated)
    );
}

#[tokio::test(start_paused = true)]
async fn a_header_that_cannot_start_a_hello_is_refused_without_waiting_for_its_body() {
    let cases: [(&str, &[u8]); 4] = [
        ("alert record", &[21, 3, 3, 0, 2]),
        ("record version 2", &[22, 2, 1, 0, 64]),
        ("empty record", &[22, 3, 1, 0, 0]),
        ("plain http", b"GET / HTTP/1.1\r\n"),
    ];
    for (name, header) in cases {
        let (mut near, mut far) = duplex(64);
        far.write_all(header).await.unwrap();
        let start = Instant::now();
        assert_eq!(
            capture_client_hello(&mut near, start + Duration::from_secs(10)).await,
            Err(HelloError::Malformed),
            "{name}"
        );
        assert_eq!(start.elapsed(), Duration::ZERO, "{name}");
        drop(far);
    }
}
