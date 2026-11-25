use crate::control::Control;
use crate::revocation::holder_revoked;
use crate::revocation_audit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Channel {
    WebSession,
    WebLogin,
    ApiToken,
    Certificate,
    DeviceApproval,
}

impl Channel {
    const fn phase(self) -> &'static str {
        match self {
            Channel::WebSession => "web_session",
            Channel::WebLogin => "web_login",
            Channel::ApiToken => "api_token",
            Channel::Certificate => "certificate",
            Channel::DeviceApproval => "device_approval",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Revoked,
    Unavailable,
}

pub(crate) async fn refuse_revoked(
    control: &Control,
    user_id: &str,
    serial: Option<i64>,
    channel: Channel,
) -> Result<(), Refusal> {
    match holder_revoked(&control.store, user_id, serial).await {
        Ok(false) => Ok(()),
        Ok(true) => {
            revocation_audit::principal_refused(user_id, channel.phase());
            Err(Refusal::Revoked)
        }
        Err(err) => {
            tracing::error!(
                target: "jaunt::control",
                error = %err,
                phase = channel.phase(),
                "checking the user revocation failed"
            );
            Err(Refusal::Unavailable)
        }
    }
}
