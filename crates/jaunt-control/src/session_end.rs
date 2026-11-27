use jaunt_proto::{ControlError as PlaneError, NodeCaller, SessionEnd, SessionEndOutcome};
use jaunt_store::{EndOutcome, EndRejection, EndSession};

use crate::control::Control;
use crate::plane::{check_fields, clock_failure, store_failure};
use crate::recordings;
use crate::session_audit::{self, Ended};

pub(crate) async fn session_end(
    control: &Control,
    caller: NodeCaller,
    request: SessionEnd,
) -> Result<SessionEndOutcome, PlaneError> {
    let control = control.clone();
    match tokio::spawn(async move { end_and_reconcile(&control, caller, request).await }).await {
        Ok(outcome) => outcome,
        Err(err) if err.is_cancelled() => {
            tracing::warn!(target: "jaunt::control", "ending a session was cancelled by the runtime shutting down");
            Err(PlaneError::Store)
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "ending a session panicked");
            Err(PlaneError::Store)
        }
    }
}

async fn end_and_reconcile(
    control: &Control,
    caller: NodeCaller,
    request: SessionEnd,
) -> Result<SessionEndOutcome, PlaneError> {
    let NodeCaller(node_id) = caller;
    check_fields(&[&node_id, &request.session_id])?;
    let bytes_in = i64::try_from(request.bytes_in).map_err(|_| PlaneError::InvalidRequest)?;
    let bytes_out = i64::try_from(request.bytes_out).map_err(|_| PlaneError::InvalidRequest)?;
    let now = control.now().ok_or_else(clock_failure)?;
    let outcome = control
        .store
        .sessions()
        .end(EndSession {
            id: &request.session_id,
            node_id: &node_id,
            exit_status: request.exit_status,
            bytes_in,
            bytes_out,
            recording_incomplete: request.recording_incomplete,
            now: now.secs,
        })
        .await
        .map_err(store_failure("ending the session"))?;
    match outcome {
        EndOutcome::Ended(session) => {
            session_audit::ended(&Ended {
                session_id: &session.id,
                user_id: &session.user_id,
                serial: session.serial,
                node_id: &session.node_id,
                login: session.login.as_deref(),
                exit_status: request.exit_status,
                bytes_in,
                bytes_out,
                recording_incomplete: request.recording_incomplete,
            });
            recordings::reconcile_after_end(
                control,
                &session.id,
                &session.node_id,
                request.recording_incomplete,
            )
            .await;
            Ok(SessionEndOutcome::Recorded)
        }
        EndOutcome::Repeated => {
            recordings::reconcile_after_end(
                control,
                &request.session_id,
                &node_id,
                request.recording_incomplete,
            )
            .await;
            Ok(SessionEndOutcome::Recorded)
        }
        EndOutcome::Late(session) => {
            session_audit::late_end(&session);
            recordings::reconcile_after_end(
                control,
                &session.id,
                &session.node_id,
                request.recording_incomplete,
            )
            .await;
            Ok(SessionEndOutcome::Recorded)
        }
        EndOutcome::Rejected(rejection) => {
            if rejection == EndRejection::ClosedByControl {
                tracing::warn!(
                    target: "jaunt::control",
                    node_id = %node_id,
                    session_id = %request.session_id,
                    exit_status = request.exit_status,
                    bytes_in,
                    bytes_out,
                    "an agent reported the end of a session that control had already closed and counted"
                );
            }
            session_audit::end_rejected(&node_id, &request.session_id, rejection_code(rejection));
            Ok(SessionEndOutcome::Rejected)
        }
    }
}

pub(crate) const fn rejection_code(rejection: EndRejection) -> &'static str {
    match rejection {
        EndRejection::UnknownSession => "session_unknown",
        EndRejection::WrongNode => "wrong_node",
        EndRejection::NotActive => "session_not_active",
        EndRejection::ConflictingEnd => "conflicting_end",
        EndRejection::ClosedByControl => "session_closed",
    }
}
