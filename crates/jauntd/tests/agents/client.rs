use std::sync::{Arc, Mutex};

use bytes::Bytes;
use h2::client::ResponseFuture;
use http::{Method, Request};
use jaunt_tunnel::ALPN_AGENT_API;
use tokio::task::JoinHandle;

use crate::frames::ServerFrames;
use crate::support::{AGENTS_NAME, EnrolledAgent, Harness, dial};

pub struct ApiClient {
    pub sender: h2::client::SendRequest<Bytes>,
    pub goaway_codes: Arc<Mutex<Vec<u32>>>,
    pub ended: JoinHandle<()>,
}

pub struct StalledRequest {
    pub response: ResponseFuture,
    _body: h2::SendStream<Bytes>,
}

impl ApiClient {
    pub async fn open(harness: &Harness, agent: &EnrolledAgent) -> ApiClient {
        let dialed = dial(harness, agent.chain.clone(), agent.key(), ALPN_AGENT_API).await;
        let (tap, goaway_codes) = ServerFrames::new(dialed.stream.unwrap());
        let (sender, connection) = h2::client::handshake(tap).await.unwrap();
        let ended = tokio::spawn(async move { drop(connection.await) });
        ApiClient {
            sender,
            goaway_codes,
            ended,
        }
    }

    pub fn saw_only_graceful_goaway(&self) -> bool {
        let codes = self.goaway_codes.lock().unwrap();
        !codes.is_empty() && codes.iter().all(|code| *code == 0)
    }

    pub async fn stalled_renew(&self) -> StalledRequest {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{AGENTS_NAME}/v1/agent/renew"))
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let mut ready = self.sender.clone().ready().await.unwrap();
        let (response, mut body) = ready.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"{"), false).unwrap();
        StalledRequest {
            response,
            _body: body,
        }
    }
}
