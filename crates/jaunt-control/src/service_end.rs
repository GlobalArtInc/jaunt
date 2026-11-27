use jaunt_proto::{ControlError as PlaneError, NodeCaller, ServiceEnd, SessionEndOutcome};
use jaunt_store::{EndOutcome, EndRejection, EndService};

use crate::control::Control;
use crate::plane::{check_fields, clock_failure, store_failure};
use crate::service_session_audit;
use crate::session_audit;
use crate::session_end::rejection_code;

pub(crate) async fn service_end(
    control: &Control,
    caller: NodeCaller,
    request: ServiceEnd,
) -> Result<SessionEndOutcome, PlaneError> {
    let control = control.clone();
    match tokio::spawn(async move { end(&control, caller, request).await }).await {
        Ok(outcome) => outcome,
        Err(err) if err.is_cancelled() => {
            tracing::warn!(target: "jaunt::control", "ending a service session was cancelled by the runtime shutting down");
            Err(PlaneError::Store)
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "ending a service session panicked");
            Err(PlaneError::Store)
        }
    }
}

async fn end(
    control: &Control,
    caller: NodeCaller,
    request: ServiceEnd,
) -> Result<SessionEndOutcome, PlaneError> {
    let NodeCaller(node_id) = caller;
    check_fields(&[&node_id, &request.session_id])?;
    let bytes_in = i64::try_from(request.bytes_in).map_err(|_| PlaneError::InvalidRequest)?;
    let bytes_out = i64::try_from(request.bytes_out).map_err(|_| PlaneError::InvalidRequest)?;
    let now = control.now().ok_or_else(clock_failure)?;
    let outcome = control
        .store
        .service_sessions()
        .end(&EndService {
            id: &request.session_id,
            node_id: &node_id,
            outcome: request.outcome.as_str(),
            bytes_in,
            bytes_out,
            now: now.secs,
        })
        .await
        .map_err(store_failure("ending the service session"))?;
    match outcome {
        EndOutcome::Ended(session) => {
            service_session_audit::ended(&session, false);
            Ok(SessionEndOutcome::Recorded)
        }
        EndOutcome::Late(session) => {
            service_session_audit::ended(&session, true);
            Ok(SessionEndOutcome::Recorded)
        }
        EndOutcome::Repeated => Ok(SessionEndOutcome::Recorded),
        EndOutcome::Rejected(rejection) => {
            if rejection == EndRejection::ClosedByControl {
                tracing::warn!(
                    target: "jaunt::control",
                    node_id = %node_id,
                    session_id = %request.session_id,
                    bytes_in,
                    bytes_out,
                    "an agent reported the end of a service session that control had already closed and counted"
                );
            }
            session_audit::end_rejected(&node_id, &request.session_id, rejection_code(rejection));
            Ok(SessionEndOutcome::Rejected)
        }
    }
}
