use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_proto::ADMIN_WHOAMI_PATH;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssh_key::Certificate;
use ssh_key::public::KeyData;

use crate::admin_signature::{
    AgentSigner, KeyFileSigner, RequestToSign, SignError, SshSigner, certificate_header, new_nonce,
    sign_request,
};
use crate::agent_protocol::{AgentClient, AgentProtocolError};
use crate::client::{ApiClient, ApiError};
use crate::display::printable;
use crate::status::Session;
use crate::store::{ProfileStore, StoreError};

pub const AGENT_TIMEOUT: Duration = Duration::from_secs(10);

const FORBIDDEN: u16 = 403;
const NOT_FOUND: u16 = 404;
const TOO_MANY: u16 = 429;
const NONE_SHOWN: &str = "-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminIdentity {
    pub user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug)]
pub struct NoKey(pub Option<AgentProtocolError>);

impl fmt::Display for NoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "the session key is not loaded in ssh-agent and the profile keeps no key file; run `jaunt login`",
        )?;
        match &self.0 {
            Some(err) => write!(f, " ({err})"),
            None => Ok(()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("not signed in: run `jaunt login`")]
    NotSignedIn,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sign(#[from] SignError),
    #[error("{0}")]
    NoKey(NoKey),
    #[error("the system clock is set before 1970")]
    Clock,
    #[error(
        "the server refused the signed request: the address of the server in this profile must equal the server's public address, the system clock must be correct, and the sign-in must not be expired or revoked (run `jaunt login` again)"
    )]
    Refused,
    #[error("your roles do not grant the administrator right this command needs")]
    Forbidden,
    #[error(
        "the server has no administrator API at this address; it may have the web console disabled"
    )]
    NotFound,
    #[error("too many signed requests, retry later")]
    TooMany,
    #[error(transparent)]
    Api(ApiError),
}

pub struct AdminContext<'a> {
    pub store: &'a ProfileStore,
    pub agent_socket: Option<&'a OsString>,
    pub clock: &'a dyn Fn() -> SystemTime,
    pub agent_timeout: Duration,
}

pub fn choose_signer(
    store: &ProfileStore,
    agent_socket: Option<&OsString>,
    key: &KeyData,
    timeout: Duration,
) -> Result<Box<dyn SshSigner>, AdminError> {
    let mut agent_problem = None;
    if let Some(socket) = agent_socket.filter(|socket| !socket.is_empty()) {
        let socket = PathBuf::from(socket);
        match AgentClient::new(socket.clone(), timeout).holds(key) {
            Ok(true) => return Ok(Box::new(AgentSigner::new(socket, timeout))),
            Ok(false) => {}
            Err(err) => agent_problem = Some(err),
        }
    }
    match store.read_private_key()? {
        Some(pem) => Ok(Box::new(KeyFileSigner::from_openssh(&pem)?)),
        None => Err(AdminError::NoKey(NoKey(agent_problem))),
    }
}

pub fn whoami(context: &AdminContext<'_>) -> Result<AdminIdentity, AdminError> {
    let session = Session::load(context.store)?.ok_or(AdminError::NotSignedIn)?;
    let client = ApiClient::new(&session.server).map_err(AdminError::Api)?;
    signed_get(context, &client, ADMIN_WHOAMI_PATH)
}

fn signed_get<T: DeserializeOwned>(
    context: &AdminContext<'_>,
    client: &ApiClient,
    path: &str,
) -> Result<T, AdminError> {
    let line = context
        .store
        .read_certificate_line()?
        .ok_or(AdminError::NotSignedIn)?;
    let text = certificate_header(&line).ok_or(SignError::Certificate)?;
    let certificate = Certificate::from_openssh(&text).map_err(|_| SignError::Certificate)?;
    let signer = choose_signer(
        context.store,
        context.agent_socket,
        certificate.public_key(),
        context.agent_timeout,
    )?;
    let created = unix_secs((context.clock)()).ok_or(AdminError::Clock)?;
    let nonce = new_nonce()?;
    let target = client.endpoint_url(path).map_err(AdminError::Api)?;
    let request = RequestToSign {
        method: "GET",
        target_uri: target.as_str(),
        body: b"",
    };
    let signed = sign_request(signer.as_ref(), &line, request, created, &nonce)?;
    client.get_signed(target, &signed).map_err(|err| match err {
        ApiError::Unauthorized => AdminError::Refused,
        ApiError::Rejected { status: FORBIDDEN } => AdminError::Forbidden,
        ApiError::Rejected { status: NOT_FOUND } => AdminError::NotFound,
        ApiError::Rejected { status: TOO_MANY } => AdminError::TooMany,
        other => AdminError::Api(other),
    })
}

fn unix_secs(time: SystemTime) -> Option<i64> {
    let secs = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(secs).ok()
}

pub fn render_identity(identity: &AdminIdentity) -> String {
    let name = identity.display_name.as_deref().unwrap_or(NONE_SHOWN);
    let groups = if identity.groups.is_empty() {
        NONE_SHOWN.to_owned()
    } else {
        identity.groups.join(", ")
    };
    format!(
        "User ID: {}\nEmail:   {}\nName:    {}\nGroups:  {}",
        printable(&identity.user_id),
        printable(&identity.email),
        printable(name),
        printable(&groups)
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::time::Duration;

    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    use super::{AdminError, AdminIdentity, choose_signer, render_identity};
    use crate::profile::ProfileName;
    use crate::store::ProfileStore;

    #[test]
    fn without_an_agent_or_a_key_file_the_error_says_to_sign_in_again() {
        let home = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(home.path(), &ProfileName::default_name());
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let missing = OsString::from(home.path().join("no-agent.sock"));

        let outcome = choose_signer(
            &store,
            Some(&missing),
            key.public_key().key_data(),
            Duration::from_secs(1),
        );

        let Err(AdminError::NoKey(no_key)) = outcome else {
            panic!("a signer was chosen without any key");
        };
        assert!(no_key.0.is_some());
        assert!(no_key.to_string().contains("run `jaunt login`"));
    }

    #[test]
    fn the_identity_is_rendered_without_terminal_controls() {
        let text = render_identity(&AdminIdentity {
            user_id: "u-1".to_owned(),
            email: "a@example.com\u{1b}[2J".to_owned(),
            display_name: None,
            groups: Vec::new(),
        });
        assert!(!text.contains('\u{1b}'));
        assert!(text.contains("Name:    -"));
        assert!(text.contains("Groups:  -"));
    }
}
