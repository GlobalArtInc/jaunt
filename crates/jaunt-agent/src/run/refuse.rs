use std::sync::atomic::{AtomicU64, Ordering};

use jaunt_tunnel::{BoxFuture, IncomingStream, StreamHandler};
use tokio::io::AsyncWriteExt;

#[derive(Default)]
pub struct RefusingHandler {
    refused: AtomicU64,
}

impl StreamHandler for RefusingHandler {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let refused = self
            .refused
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        tracing::info!(
            target: "jaunt::agent",
            session = %stream.meta.session(),
            kind = stream.meta.kind().as_str(),
            client = stream.meta.client(),
            refused_streams = refused,
            "refused a stream: this agent does not serve sessions yet"
        );
        let mut io = stream.io;
        Box::pin(async move {
            if let Err(error) = io.shutdown().await {
                tracing::debug!(
                    target: "jaunt::agent",
                    error = %error,
                    "closing a refused stream failed"
                );
            }
        })
    }
}
