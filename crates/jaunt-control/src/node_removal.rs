use jaunt_store::{OpenSessions, SessionEndReason, StoreError};

use crate::control::Control;
use crate::killer::{KillReason, KillScope};
use crate::session_audit;

#[derive(Debug, thiserror::Error)]
pub(crate) enum CutOffError {
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

pub(crate) async fn cut_off(control: &Control, node_id: &str) -> Result<usize, CutOffError> {
    let scope = KillScope::Node {
        node_id: node_id.to_owned(),
    };
    let Some(now) = control.now() else {
        control
            .killer
            .order(scope, KillReason::NodeRemoved, &[])
            .await;
        return Err(CutOffError::Clock);
    };
    let closed = control
        .store
        .sessions()
        .close(
            OpenSessions::OfNode(node_id),
            SessionEndReason::NodeRemoved,
            now.secs,
        )
        .await;
    match closed {
        Ok(closed) => {
            for session in &closed {
                session_audit::closed(session, SessionEndReason::NodeRemoved);
            }
            control
                .killer
                .order(scope, KillReason::NodeRemoved, &closed)
                .await;
            Ok(closed.len())
        }
        Err(err) => {
            control
                .killer
                .order(scope, KillReason::NodeRemoved, &[])
                .await;
            Err(CutOffError::Store(err))
        }
    }
}
