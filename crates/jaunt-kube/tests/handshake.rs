use http::header::{HeaderMap, HeaderName, HeaderValue};
use jaunt_kube::{
    ChannelProtocol, SubprotocolError, protocol_from_response, rewrite_subprotocol_offer,
    select_offered_subprotocol, strip_websocket_extensions,
};

const TOKEN_OFFER: &str = "base64url.bearer.authorization.k8s.io.c2VrcmV0LXRva2Vu";

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn offer(values: &[&str]) -> HeaderMap {
    let pairs: Vec<(&str, &str)> = values
        .iter()
        .map(|value| ("Sec-WebSocket-Protocol", *value))
        .collect();
    headers(&pairs)
}

#[test]
fn the_first_offered_binary_channel_protocol_wins() {
    use ChannelProtocol::{V4, V5};
    let token_then_v5 = format!("{TOKEN_OFFER}, v5.channel.k8s.io");
    for (values, selected) in [
        (&[][..], None),
        (&["v5.channel.k8s.io"][..], Some(V5)),
        (&["v4.channel.k8s.io"][..], Some(V4)),
        (&["v5.channel.k8s.io, v4.channel.k8s.io"][..], Some(V5)),
        (&["v4.channel.k8s.io,v5.channel.k8s.io"][..], Some(V4)),
        (&["v4.channel.k8s.io", "v5.channel.k8s.io"][..], Some(V4)),
        (&["channel.k8s.io", "v5.channel.k8s.io"][..], Some(V5)),
        (&["  v5.channel.k8s.io\t ,v4.channel.k8s.io"][..], Some(V5)),
        (&["V5.channel.k8s.io", "v5.CHANNEL.k8s.io"][..], None),
        (&[TOKEN_OFFER][..], None),
        (&[token_then_v5.as_str()][..], Some(V5)),
        (
            &["v4.base64.channel.k8s.io, base64.channel.k8s.io, channel.k8s.io"][..],
            None,
        ),
        (&["v5.channel.k8s.io, v5.channel.k8s.io"][..], Some(V5)),
        (&["", ",", " , ,v4.channel.k8s.io"][..], Some(V4)),
        (&["v5.channel.k8s.io.extra", "xv5.channel.k8s.io"][..], None),
    ] {
        assert_eq!(
            select_offered_subprotocol(&offer(values)),
            selected,
            "{values:?}"
        );
    }
}

#[test]
fn the_rewritten_offer_carries_only_the_selected_protocol() {
    let mut map = offer(&[TOKEN_OFFER, "v4.channel.k8s.io, v5.channel.k8s.io"]);
    map.append("accept", HeaderValue::from_static("*/*"));
    assert_eq!(
        rewrite_subprotocol_offer(&mut map),
        Some(ChannelProtocol::V4)
    );
    let left: Vec<&HeaderValue> = map.get_all("sec-websocket-protocol").iter().collect();
    assert_eq!(left, [&HeaderValue::from_static("v4.channel.k8s.io")]);
    assert!(map.contains_key("accept"));

    let mut token_only = offer(&[TOKEN_OFFER, "base64.channel.k8s.io"]);
    assert_eq!(rewrite_subprotocol_offer(&mut token_only), None);
    assert!(!token_only.contains_key("sec-websocket-protocol"));
}

#[test]
fn the_response_protocol_must_be_the_single_offered_one() {
    use ChannelProtocol::{V4, V5};
    for (values, offered, result) in [
        (&["v5.channel.k8s.io"][..], V5, Ok(V5)),
        (&[" v4.channel.k8s.io "][..], V4, Ok(V4)),
        (
            &["v4.channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Mismatch),
        ),
        (&[][..], V5, Err(SubprotocolError::Missing)),
        (&[""][..], V5, Err(SubprotocolError::Missing)),
        (
            &["v5.channel.k8s.io", "v5.channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Ambiguous),
        ),
        (
            &["v5.channel.k8s.io, v4.channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Ambiguous),
        ),
        (
            &["channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Unsupported),
        ),
        (
            &["base64.channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Unsupported),
        ),
        (
            &["V5.channel.k8s.io"][..],
            V5,
            Err(SubprotocolError::Unsupported),
        ),
        (&[TOKEN_OFFER][..], V5, Err(SubprotocolError::Unsupported)),
    ] {
        assert_eq!(
            protocol_from_response(&offer(values), offered),
            result,
            "{values:?}"
        );
    }
    let mut unreadable = HeaderMap::new();
    unreadable.insert(
        "sec-websocket-protocol",
        HeaderValue::from_bytes(b"v5.channel.k8s.io\xff").unwrap(),
    );
    assert_eq!(
        protocol_from_response(&unreadable, V5),
        Err(SubprotocolError::Unreadable)
    );
}

#[test]
fn websocket_extensions_are_always_stripped() {
    let mut map = headers(&[
        (
            "Sec-WebSocket-Extensions",
            "permessage-deflate; client_max_window_bits",
        ),
        ("sec-websocket-extensions", "x-other"),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
    ]);
    assert!(strip_websocket_extensions(&mut map));
    assert!(!map.contains_key("sec-websocket-extensions"));
    assert!(map.contains_key("sec-websocket-key"));
    assert!(!strip_websocket_extensions(&mut map));
}
