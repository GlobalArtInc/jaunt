use std::future::Future;
use std::pin::Pin;

use crate::service_session::{
    LocateServiceRequest, ServiceAuthorizeDecision, ServiceAuthorizeRequest, ServiceEnd,
    ServiceLocation, ServiceRouteRequest,
};
use crate::session::{
    AuthorizeDecision, AuthorizeRequest, NodeCaller, RouteDecision, RouteRequest, SessionEnd,
    SessionEndOutcome,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    #[error("the request is malformed")]
    InvalidRequest,
    #[error("the control store failed")]
    Store,
    #[error("the control clock is before the unix epoch")]
    Clock,
}

pub trait ControlPlane: Send + Sync {
    fn route(&self, request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>>;

    fn authorize(
        &self,
        node: NodeCaller,
        request: AuthorizeRequest,
    ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>>;

    fn session_end(
        &self,
        node: NodeCaller,
        request: SessionEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>>;

    fn locate_service(
        &self,
        _request: LocateServiceRequest,
    ) -> BoxFuture<'_, Result<Option<ServiceLocation>, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn route_service(
        &self,
        _request: ServiceRouteRequest,
    ) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn authorize_service(
        &self,
        _node: NodeCaller,
        _request: ServiceAuthorizeRequest,
    ) -> BoxFuture<'_, Result<ServiceAuthorizeDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn service_end(
        &self,
        _node: NodeCaller,
        _request: ServiceEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }
}
