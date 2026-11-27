mod entry_support;

use std::net::SocketAddr;
use std::time::Duration;

use entry_support::*;
use jaunt_gate::{ALPN_SSH, MAX_CLIENT_HELLO_BYTES, TlsEntry, TlsEntryConfig, TlsRefusal};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::time::{Instant, sleep};

#[tokio::test]
async fn a_trusted_proxy_names_the_client_and_the_per_address_limit_follows_that_name() {
    let mut config = proxied(config());
    config.front_limits = limits(1);
    let entry = TlsEntry::new(config).unwrap();
    let client = addr("203.0.113.7:51000");
    let hello = hello(AGENTS, &[]);
    let (near, _far) = sent(&[&proxy_header(client), &hello]).await;
    let first = entry.admit(near, addr("10.0.0.5:30000")).await.unwrap();
    assert_eq!(first.route.client_addr, client);
    assert_eq!(first.route.peer_addr, addr("10.0.0.5:30000"));
    assert!(first.route.proxied);
    assert_eq!(first.stream.pending(), hello.as_slice());

    let (near, _far) = sent(&[&proxy_header(addr("203.0.113.8:51000")), &hello]).await;
    assert!(entry.admit(near, addr("10.0.0.5:30001")).await.is_ok());
    let (near, _far) = sent(&[&proxy_header(addr("203.0.113.7:51001")), &hello]).await;
    assert_eq!(
        entry.admit(near, addr("10.0.0.6:30002")).await.err(),
        Some(TlsRefusal::Limit)
    );
    drop(first);
    let (near, _far) = sent(&[&proxy_header(addr("203.0.113.7:51002")), &hello]).await;
    assert!(entry.admit(near, addr("10.0.0.6:30003")).await.is_ok());

    let local = [PROXY_SIGNATURE, &[0x20, 0x00, 0, 0]].concat();
    let (near, _far) = sent(&[&local, &hello]).await;
    let health = entry.admit(near, addr("10.0.0.9:30004")).await.unwrap();
    assert_eq!(health.route.client_addr, addr("10.0.0.9:30004"));
    assert!(!health.route.proxied);
    let (near, _far) = sent(&[&local, &hello]).await;
    let second_health = entry.admit(near, addr("10.0.0.9:30005")).await.unwrap();
    drop((health, second_health));
    assert_eq!(entry.refused(TlsRefusal::Limit), 1);
}

#[tokio::test]
async fn the_proxy_header_is_mandatory_bounded_and_believed_only_from_trusted_peers() {
    let entry = TlsEntry::new(proxied(config())).unwrap();
    let hello = hello(AGENTS, &[]);
    let header = proxy_header(addr("203.0.113.7:51000"));
    let mut bad_family = header.clone();
    bad_family[13] = 0x31;
    let oversized = [PROXY_SIGNATURE, &[0x21, 0x11], &be16(513), &[0; 513]].concat();
    let cases: Vec<(&str, &str, Vec<u8>, TlsRefusal)> = vec![
        (
            "untrusted peer",
            "192.0.2.1:4000",
            [&header[..], &hello].concat(),
            TlsRefusal::ProxyUntrusted,
        ),
        (
            "hello without header",
            "10.0.0.5:4000",
            hello.clone(),
            TlsRefusal::ProxyMalformed,
        ),
        (
            "bad family",
            "10.0.0.5:4000",
            [&bad_family[..], &hello].concat(),
            TlsRefusal::ProxyMalformed,
        ),
        (
            "too long",
            "10.0.0.5:4000",
            oversized,
            TlsRefusal::ProxyMalformed,
        ),
        (
            "cut header",
            "10.0.0.5:4000",
            header[..20].to_vec(),
            TlsRefusal::ProxyMalformed,
        ),
    ];
    for (name, peer, bytes, expected) in cases {
        let (near, mut far) = sent(&[&bytes]).await;
        far.shutdown().await.unwrap();
        assert_eq!(
            entry.admit(near, addr(peer)).await.err(),
            Some(expected),
            "{name}"
        );
    }
    assert_eq!(entry.refused(TlsRefusal::ProxyUntrusted), 1);
    assert_eq!(entry.refused(TlsRefusal::ProxyMalformed), 4);

    let direct = TlsEntry::new(config()).unwrap();
    let (near, _far) = sent(&[&header, &hello]).await;
    assert_eq!(
        direct.admit(near, addr("10.0.0.5:4000")).await.err(),
        Some(TlsRefusal::BadHello)
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_proxy_header_is_cut_after_five_seconds() {
    let entry = TlsEntry::new(proxied(config())).unwrap();
    let (near, _far) = duplex(64);
    let start = Instant::now();
    assert_eq!(
        entry.admit(near, addr("10.0.0.5:4000")).await.err(),
        Some(TlsRefusal::ProxyTimeout)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(5));

    let (near, mut far) = duplex(64);
    let trickle = tokio::spawn(async move {
        for byte in proxy_header(addr("203.0.113.7:51000")) {
            if far.write_all(&[byte]).await.is_err() {
                return;
            }
            sleep(Duration::from_secs(1)).await;
        }
    });
    let start = Instant::now();
    assert_eq!(
        entry.admit(near, addr("10.0.0.5:4000")).await.err(),
        Some(TlsRefusal::ProxyTimeout)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(5));
    trickle.await.unwrap();
    assert_eq!(entry.refused(TlsRefusal::ProxyTimeout), 2);
}

#[tokio::test(start_paused = true)]
async fn a_slow_hello_after_admission_is_refused_at_ten_seconds_and_counted() {
    let entry = TlsEntry::new(config()).unwrap();
    let (near, _far) = duplex(64);
    let start = Instant::now();
    assert_eq!(
        entry.admit(near, addr("198.51.100.9:4000")).await.err(),
        Some(TlsRefusal::HelloTimeout)
    );
    assert_eq!(start.elapsed(), Duration::from_secs(10));
    let over = hello_of_size(MAX_CLIENT_HELLO_BYTES + 1, SINGLE_RECORD);
    let (near, _far) = sent(&[&over[..5]]).await;
    assert_eq!(
        entry.admit(near, addr("198.51.100.9:4001")).await.err(),
        Some(TlsRefusal::HelloTooLarge)
    );
    assert_eq!(entry.refused(TlsRefusal::HelloTimeout), 1);
    assert_eq!(entry.refused(TlsRefusal::HelloTooLarge), 1);
}

#[tokio::test(start_paused = true)]
async fn each_reason_is_logged_on_its_own_with_the_client_named_by_the_header() {
    install_recorder();
    let entry = TlsEntry::new(proxied(config())).unwrap();
    let header = proxy_header(addr("203.0.113.7:51000"));
    for port in [1, 2, 3] {
        let (near, _far) = sent(&[&header, b"GET / HTTP/1.1\r\n\r\n"]).await;
        let refused = entry.admit(near, SocketAddr::from(([10, 0, 0, 5], port)));
        assert_eq!(refused.await.err(), Some(TlsRefusal::BadHello));
    }
    for port in [4, 5] {
        let (near, _far) = sent(&[&header]).await;
        let refused = entry.admit(near, SocketAddr::from(([192, 0, 2, 5], port)));
        assert_eq!(refused.await.err(), Some(TlsRefusal::ProxyUntrusted));
    }
    let logged = || -> Vec<(String, String, String)> {
        audit_events()
            .into_iter()
            .filter(|event| event.get("event").map(String::as_str) == Some("gate.tls.refused"))
            .map(|event| {
                (
                    event["reason"].clone(),
                    event["client"].clone(),
                    event["suppressed"].clone(),
                )
            })
            .collect()
    };
    let first = |reason: &str, client: &str, suppressed: &str| {
        (reason.to_owned(), client.to_owned(), suppressed.to_owned())
    };
    assert_eq!(
        logged(),
        [
            first("bad_hello", "203.0.113.7", "0"),
            first("proxy_untrusted", "192.0.2.5", "0")
        ]
    );
    sleep(Duration::from_secs(10)).await;
    let (near, _far) = sent(&[&header, b"GET / HTTP/1.1\r\n\r\n"]).await;
    let refused = entry.admit(near, addr("10.0.0.5:6"));
    assert_eq!(refused.await.err(), Some(TlsRefusal::BadHello));
    assert_eq!(
        logged().last(),
        Some(&first("bad_hello", "203.0.113.7", "2"))
    );
    assert_eq!(audit_events()[0]["level"], "INFO");
    assert_eq!(entry.refused(TlsRefusal::BadHello), 4);
    assert_eq!(entry.refused(TlsRefusal::ProxyUntrusted), 2);
}

#[tokio::test(start_paused = true)]
async fn the_global_handshake_limit_is_checked_before_the_proxy_header_is_read() {
    let mut config = proxied(config());
    config.max_handshaking = 1;
    let entry = std::sync::Arc::new(TlsEntry::new(config).unwrap());
    let (silent, _quiet) = duplex(64);
    let waiting = {
        let entry = std::sync::Arc::clone(&entry);
        tokio::spawn(async move { entry.admit(silent, addr("10.0.0.5:4000")).await.err() })
    };
    for _ in 0..1000 {
        if entry.handshaking() == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(entry.handshaking(), 1);
    let (second, _far) = duplex(64);
    let start = Instant::now();
    assert_eq!(
        entry.admit(second, addr("10.0.0.6:4000")).await.err(),
        Some(TlsRefusal::Limit)
    );
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(waiting.await.unwrap(), Some(TlsRefusal::ProxyTimeout));
}

#[tokio::test(start_paused = true)]
async fn every_refusal_gives_back_the_handshake_budget_and_the_address_slot() {
    let tight = |mut config: TlsEntryConfig| {
        config.max_handshaking = 1;
        config.front_limits = limits(1);
        TlsEntry::new(config).unwrap()
    };
    let direct = tight(config());
    let behind = tight(proxied(config()));
    let agent = hello(AGENTS, &[]);
    let agent_behind = [&proxy_header(addr("203.0.113.7:51000"))[..], &agent].concat();
    let over = hello_of_size(MAX_CLIENT_HELLO_BYTES + 1, SINGLE_RECORD);
    let no_sni = records(&hello_message(None, &[ALPN_SSH], 0), SINGLE_RECORD);
    type Case<'a> = (&'a TlsEntry, &'a str, &'a [u8], Vec<u8>, TlsRefusal);
    let cases: Vec<Case> = vec![
        (
            &direct,
            "198.51.100.9:4000",
            &agent,
            hello("example.com", &[]),
            TlsRefusal::UnknownSni,
        ),
        (
            &direct,
            "198.51.100.9:4000",
            &agent,
            no_sni,
            TlsRefusal::NoSni,
        ),
        (
            &direct,
            "198.51.100.9:4000",
            &agent,
            hello(DOMAIN, &[b"h2"]),
            TlsRefusal::AlpnUnsupported,
        ),
        (
            &direct,
            "198.51.100.9:4000",
            &agent,
            over[..5].to_vec(),
            TlsRefusal::HelloTooLarge,
        ),
        (
            &direct,
            "198.51.100.9:4000",
            &agent,
            b"GET / HTTP/1.1\r\n".to_vec(),
            TlsRefusal::BadHello,
        ),
        (
            &behind,
            "10.0.0.5:4000",
            &agent_behind,
            agent.clone(),
            TlsRefusal::ProxyMalformed,
        ),
        (
            &behind,
            "10.0.0.5:4000",
            &agent_behind,
            Vec::new(),
            TlsRefusal::ProxyTimeout,
        ),
    ];
    for (entry, peer, follow_up, bytes, reason) in cases {
        let (near, _far) = sent(&[&bytes]).await;
        assert_eq!(entry.admit(near, addr(peer)).await.err(), Some(reason));
        assert_eq!(entry.handshaking(), 0, "{reason:?}");
        for _ in 0..8 {
            let (near, _far) = sent(&[follow_up]).await;
            let admitted = entry.admit(near, addr(peer)).await;
            assert!(admitted.is_ok(), "{reason:?}");
        }
    }
}

#[tokio::test]
async fn the_front_limit_is_checked_before_any_byte_and_kube_has_its_own_limit() {
    let mut config = config();
    config.front_limits = limits(2);
    config.kube_limits = limits(1);
    let entry = TlsEntry::new(config).unwrap();
    let peer = addr("198.51.100.9:4000");
    let kube_hello = hello(&format!("prod.kube.{DOMAIN}"), &[b"h2"]);
    let (near, _far) = sent(&[&kube_hello]).await;
    let pass_through = entry.admit(near, peer).await.unwrap();
    assert!(pass_through.stream_slot.is_some());
    let (near, _far) = sent(&[&kube_hello]).await;
    assert_eq!(entry.admit(near, peer).await.err(), Some(TlsRefusal::Limit));
    let (near, _far) = sent(&[&hello(DOMAIN, &[ALPN_SSH])]).await;
    let gate = entry.admit(near, peer).await.unwrap();
    assert!(gate.stream_slot.is_none());
    let (silent, _far) = duplex(64);
    assert_eq!(
        entry.admit(silent, peer).await.err(),
        Some(TlsRefusal::Limit)
    );
    drop((pass_through, gate));
    assert_eq!(entry.refused(TlsRefusal::Limit), 2);
}

#[tokio::test]
async fn the_global_handshake_cap_holds_until_the_handshake_slot_is_released() {
    let mut config = config();
    config.max_handshaking = 1;
    let entry = TlsEntry::new(config).unwrap();
    let (near, _far) = sent(&[&hello(AGENTS, &[])]).await;
    let held = entry.admit(near, addr("198.51.100.9:4000")).await.unwrap();
    assert_eq!(entry.handshaking(), 1);
    let (silent, _far) = duplex(64);
    assert_eq!(
        entry.admit(silent, addr("198.51.100.10:4000")).await.err(),
        Some(TlsRefusal::Limit)
    );
    drop(held.handshake);
    assert_eq!(entry.handshaking(), 0);
    let (near, _far) = sent(&[&hello(AGENTS, &[])]).await;
    assert!(entry.admit(near, addr("198.51.100.10:4000")).await.is_ok());
}
