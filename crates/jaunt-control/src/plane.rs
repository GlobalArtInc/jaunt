use jaunt_policy::NodeInfo;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, BoxFuture, ControlError as PlaneError, ControlPlane,
    NodeCaller, RouteDecision, RouteRequest, SessionEnd, SessionEndOutcome,
};
use jaunt_store::{Node, StoreError};

use crate::control::Control;
use crate::{authorize, route, session_end};

const MAX_FIELD_BYTES: usize = 256;

impl ControlPlane for Control {
    fn route(&self, request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, PlaneError>> {
        Box::pin(route::route(self, request))
    }

    fn authorize(
        &self,
        node: NodeCaller,
        request: AuthorizeRequest,
    ) -> BoxFuture<'_, Result<AuthorizeDecision, PlaneError>> {
        Box::pin(authorize::authorize(self, node, request))
    }

    fn session_end(
        &self,
        node: NodeCaller,
        request: SessionEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, PlaneError>> {
        Box::pin(session_end::session_end(self, node, request))
    }
}

pub(crate) fn check_fields(values: &[&str]) -> Result<(), PlaneError> {
    let acceptable = values
        .iter()
        .all(|value| value.len() <= MAX_FIELD_BYTES && !value.chars().any(char::is_control));
    if acceptable {
        Ok(())
    } else {
        Err(PlaneError::InvalidRequest)
    }
}

pub(crate) fn store_failure(operation: &'static str) -> impl FnOnce(StoreError) -> PlaneError {
    move |err| {
        tracing::error!(target: "jaunt::control", error = %err, operation, "a session store operation failed");
        PlaneError::Store
    }
}

pub(crate) fn clock_failure() -> PlaneError {
    tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
    PlaneError::Clock
}

pub(crate) fn node_info(node: &Node) -> NodeInfo {
    NodeInfo {
        name: node.name.clone(),
        labels: node.labels.clone(),
    }
}
