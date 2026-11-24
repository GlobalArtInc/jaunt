use std::time::{Duration, Instant};

use jaunt::client::{ApiClient, ApiError};
use jaunt::secret::Secret;
use jaunt_proto::StartRequest;

use crate::support::{API_TOKEN, RawReply, RawServer};

fn client(server: &RawServer, deadline: Duration) -> ApiClient {
    ApiClient::new(&server.server_url())
        .unwrap()
        .with_deadline(deadline)
}

fn token() -> Secret {
    Secret::new(API_TOKEN.to_owned())
}

#[test]
fn redirects_are_not_followed() {
    let server = RawServer::start(RawReply::Redirect);
    let request = StartRequest {
        code_challenge: "c".repeat(43),
        code_challenge_method: "S256".to_owned(),
        redirect_port: 40000,
        client_label: None,
    };
    let outcome = client(&server, Duration::from_secs(10)).start(&request);
    assert_eq!(outcome.err(), Some(ApiError::Rejected { status: 302 }));
    assert_eq!(server.requests(), ["POST /v1/login/start HTTP/1.1"]);
}

#[test]
fn bodies_over_one_mebibyte_are_refused_whether_announced_or_chunked() {
    for reply in [RawReply::OversizedContentLength, RawReply::OversizedChunked] {
        let server = RawServer::start(reply);
        let outcome = client(&server, Duration::from_secs(10)).whoami(&token());
        assert_eq!(outcome.err(), Some(ApiError::BodyTooLarge));
    }
}

#[test]
fn a_server_that_dribbles_its_answer_hits_the_total_deadline() {
    let server = RawServer::start(RawReply::Dribble);
    let started = Instant::now();
    let outcome = client(&server, Duration::from_millis(800)).whoami(&token());
    assert_eq!(outcome.err(), Some(ApiError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_server_that_never_answers_times_out_at_the_deadline() {
    let server = RawServer::start(RawReply::Silent);
    let started = Instant::now();
    let outcome = client(&server, Duration::from_millis(300)).whoami(&token());
    assert_eq!(outcome.err(), Some(ApiError::TimedOut));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}
