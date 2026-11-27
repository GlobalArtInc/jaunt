use jaunt_proto::{
    ServiceAuthorizeRequest, ServiceAuthorizeResponse, ServiceCertificateRequest,
    ServiceCertificateResponse, ServiceEnd, SessionEndOutcome,
};
use jaunt_tunnel::BoxFuture;

use crate::run::api::{AgentApi, ApiError};

pub trait ServiceControl: Send + Sync {
    fn authorize<'a>(
        &'a self,
        request: &'a ServiceAuthorizeRequest,
    ) -> BoxFuture<'a, Result<ServiceAuthorizeResponse, ApiError>>;

    fn end<'a>(&'a self, end: &'a ServiceEnd)
    -> BoxFuture<'a, Result<SessionEndOutcome, ApiError>>;

    fn issue_certificate<'a>(
        &'a self,
        request: &'a ServiceCertificateRequest,
    ) -> BoxFuture<'a, Result<ServiceCertificateResponse, ApiError>>;
}

impl ServiceControl for AgentApi {
    fn authorize<'a>(
        &'a self,
        request: &'a ServiceAuthorizeRequest,
    ) -> BoxFuture<'a, Result<ServiceAuthorizeResponse, ApiError>> {
        Box::pin(self.authorize_service(request))
    }

    fn end<'a>(
        &'a self,
        end: &'a ServiceEnd,
    ) -> BoxFuture<'a, Result<SessionEndOutcome, ApiError>> {
        Box::pin(self.end_service(end))
    }

    fn issue_certificate<'a>(
        &'a self,
        request: &'a ServiceCertificateRequest,
    ) -> BoxFuture<'a, Result<ServiceCertificateResponse, ApiError>> {
        Box::pin(self.service_certificate(request))
    }
}

pub fn may_have_started(error: &ApiError) -> bool {
    match error {
        ApiError::Http2(_)
        | ApiError::CallTimeout
        | ApiError::BadResponse
        | ApiError::BodyTooLarge
        | ApiError::Shutdown => true,
        ApiError::Status { status, .. } => *status >= 500,
        ApiError::ServerName
        | ApiError::ConnectTimeout
        | ApiError::Tcp(_)
        | ApiError::Tls(_)
        | ApiError::UnexpectedProtocol
        | ApiError::NodeRemoved
        | ApiError::Unauthorized
        | ApiError::Request => false,
    }
}
