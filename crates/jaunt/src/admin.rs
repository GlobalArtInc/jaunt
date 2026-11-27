use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_policy::AdminPermission;
use jaunt_proto::{
    ADMIN_TOKEN_ENV, ADMIN_TOKEN_MAX_LIVE_PER_CREATOR, ADMIN_TOKEN_MAX_TTL_SECS,
    ADMIN_TOKEN_MIN_TTL_SECS, ADMIN_TOKEN_PREFIX, ADMIN_TOKENS_PATH, ADMIN_WHOAMI_PATH, ErrorBody,
    admin_token_id, admin_token_path, is_admin_token_id,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use ssh_key::Certificate;
use ssh_key::public::KeyData;
use url::Url;
use zeroize::Zeroizing;

use crate::admin_signature::{
    AgentSigner, KeyFileSigner, RequestToSign, SignError, SignedHeaders, SshSigner,
    certificate_header, new_nonce, sign_request,
};
use crate::agent_protocol::{AgentClient, AgentProtocolError};
use crate::client::{ApiClient, ApiError};
use crate::display::{format_local, printable};
use crate::secret::Secret;
use crate::server_url::ServerUrl;
use crate::status::Session;
use crate::store::{ProfileStore, StoreError};

pub const AGENT_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_TOKEN_FILE_BYTES: u64 = 4096;

const UNAUTHORIZED: u16 = 401;
const FORBIDDEN: u16 = 403;
const NOT_FOUND: u16 = 404;
const CONFLICT: u16 = 409;
const UNPROCESSABLE: u16 = 422;
const TOO_MANY: u16 = 429;
const NONE_SHOWN: &str = "-";
const ENV_SOURCE: &str = "env";
const TRUNCATED_NOTE: &str = "Only part of the list is shown: the server sends at most 500 tokens, live ones first, then those that died in the last 7 days.";

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
    #[error(
        "an automation token is never read from the command line: write it to a file and pass the file to --token, or set {ADMIN_TOKEN_ENV} and pass `--token env`; a file whose name looks like a token must be given as a path such as ./NAME"
    )]
    TokenOnCommandLine,
    #[error("cannot read the token file given to --token")]
    TokenUnreadable,
    #[error("{ADMIN_TOKEN_ENV} is not set")]
    TokenMissing,
    #[error("the automation token is not in the {ADMIN_TOKEN_PREFIX}… form")]
    TokenMalformed,
    #[error(
        "the server refused the automation token: it may be unknown, revoked or expired, used from an address outside its networks, or its creator may have lost access"
    )]
    TokenRefused,
    #[error("a token can only carry rights you hold yourself")]
    ScopeNotHeld,
    #[error("you already have a live token with this name")]
    NameTaken,
    #[error("you already have {ADMIN_TOKEN_MAX_LIVE_PER_CREATOR} live tokens: revoke one first")]
    TooManyTokens,
    #[error("the token is already revoked")]
    AlreadyRevoked,
    #[error("no token has this id")]
    UnknownToken,
    #[error("{0}")]
    InvalidToken(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    Env,
    File(PathBuf),
}

pub fn parse_token_source(value: &str) -> Result<TokenSource, String> {
    match value {
        "" => Err("give a file or `env`".to_owned()),
        ENV_SOURCE => Ok(TokenSource::Env),
        path => Ok(TokenSource::File(PathBuf::from(path))),
    }
}

pub fn parse_ttl(text: &str) -> Result<i64, String> {
    let (digits, unit) = match text.char_indices().last() {
        Some((at, unit)) if unit.is_ascii_alphabetic() => (&text[..at], unit),
        _ => (text, 's'),
    };
    let factor = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err("use a number of seconds or a number followed by s, m, h or d".to_owned()),
    };
    let well_formed = !digits.is_empty()
        && digits.len() <= 12
        && digits.bytes().all(|byte| byte.is_ascii_digit());
    let secs = digits
        .parse::<i64>()
        .ok()
        .filter(|_| well_formed)
        .and_then(|count| count.checked_mul(factor))
        .ok_or_else(|| "use a number of seconds or a number followed by s, m, h or d".to_owned())?;
    if (ADMIN_TOKEN_MIN_TTL_SECS..=ADMIN_TOKEN_MAX_TTL_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err("the lifetime must be between 60 seconds and 90 days".to_owned())
    }
}

pub fn parse_scope(text: &str) -> Result<AdminPermission, String> {
    match text.parse::<AdminPermission>() {
        Ok(AdminPermission::TokensWrite) => Err("a token can never carry tokens.write".to_owned()),
        Ok(permission) => Ok(permission),
        Err(_) => Err(format!(
            "not an administrator right; use one of {}",
            AdminPermission::ALL
                .iter()
                .filter(|permission| **permission != AdminPermission::TokensWrite)
                .map(AdminPermission::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub fn read_admin_token(
    source: &TokenSource,
    from_environment: Option<OsString>,
) -> Result<Secret, AdminError> {
    let text = match source {
        TokenSource::Env => {
            let value = from_environment.ok_or(AdminError::TokenMissing)?;
            Zeroizing::new(
                value
                    .into_string()
                    .map_err(|_| AdminError::TokenMalformed)?,
            )
        }
        TokenSource::File(path) => read_token_file(path)?,
    };
    let trimmed = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
    if admin_token_id(trimmed).is_none() {
        return Err(AdminError::TokenMalformed);
    }
    Ok(Secret::new(trimmed.to_owned()))
}

fn read_token_file(path: &Path) -> Result<Zeroizing<String>, AdminError> {
    if admin_token_id(path.to_string_lossy().trim()).is_some() {
        return Err(AdminError::TokenOnCommandLine);
    }
    let file = File::open(path).map_err(|_| AdminError::TokenUnreadable)?;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| AdminError::TokenUnreadable)?;
    if u64::try_from(text.len()).map_or(true, |length| length > MAX_TOKEN_FILE_BYTES) {
        return Err(AdminError::TokenMalformed);
    }
    Ok(text)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub creator: String,
    pub scope: Vec<String>,
    pub cidrs: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenList {
    pub tokens: Vec<TokenSummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenIdentity {
    pub id: String,
    pub name: String,
    pub scope: Vec<String>,
    pub rights: Vec<String>,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct TokenWhoami {
    token: TokenIdentity,
}

#[derive(Deserialize)]
struct CreatedBody {
    #[serde(flatten)]
    token: TokenSummary,
    secret: String,
}

pub struct CreatedToken {
    pub token: TokenSummary,
    pub secret: Secret,
}

impl fmt::Debug for CreatedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedToken")
            .field("token", &self.token)
            .field("secret", &self.secret)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewToken {
    pub name: String,
    pub scope: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cidrs: Vec<String>,
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

fn sign_for(
    context: &AdminContext<'_>,
    client: &ApiClient,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(Url, SignedHeaders), AdminError> {
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
        method,
        target_uri: target.as_str(),
        body,
    };
    let signed = sign_request(signer.as_ref(), &line, request, created, &nonce)?;
    Ok((target, signed))
}

fn signed_exchange(
    context: &AdminContext<'_>,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>), AdminError> {
    let session = Session::load(context.store)?.ok_or(AdminError::NotSignedIn)?;
    let client = ApiClient::new(&session.server).map_err(AdminError::Api)?;
    let (target, signed) = sign_for(context, &client, method.as_str(), path, &body)?;
    client
        .exchange_signed(method, target, &signed, body)
        .map_err(AdminError::Api)
}

fn refusal(status: u16, body: &[u8]) -> AdminError {
    let code = serde_json::from_slice::<ErrorBody>(body)
        .map(|parsed| parsed.error)
        .unwrap_or_default();
    match (status, code.as_str()) {
        (UNAUTHORIZED, _) => AdminError::Refused,
        (FORBIDDEN, "scope_not_held") => AdminError::ScopeNotHeld,
        (FORBIDDEN, _) => AdminError::Forbidden,
        (NOT_FOUND, _) => AdminError::NotFound,
        (CONFLICT, "name_taken") => AdminError::NameTaken,
        (CONFLICT, "too_many_tokens") => AdminError::TooManyTokens,
        (CONFLICT, "already_revoked") => AdminError::AlreadyRevoked,
        (UNPROCESSABLE, "invalid_name") => AdminError::InvalidToken(
            "the name must be 1 to 64 lowercase letters, digits or -, starting and ending with a letter or digit",
        ),
        (UNPROCESSABLE, "invalid_scope") => AdminError::InvalidToken(
            "the scope must list administrator rights once each, without tokens.write",
        ),
        (UNPROCESSABLE, "invalid_ttl") => {
            AdminError::InvalidToken("the lifetime must be between 60 seconds and 90 days")
        }
        (UNPROCESSABLE, "invalid_cidrs") => AdminError::InvalidToken(
            "give at most 16 networks as address/prefix with a prefix longer than 0 and no bits set after it; give none to accept any address",
        ),
        (TOO_MANY, _) => AdminError::TooMany,
        _ => AdminError::Api(ApiError::Rejected { status }),
    }
}

fn decoded<T: DeserializeOwned>(status: u16, body: &[u8]) -> Result<T, AdminError> {
    if (200..300).contains(&status) {
        serde_json::from_slice(body).map_err(|_| AdminError::Api(ApiError::BadResponse))
    } else {
        Err(refusal(status, body))
    }
}

pub fn create_token(
    context: &AdminContext<'_>,
    request: &NewToken,
) -> Result<CreatedToken, AdminError> {
    let body = serde_json::to_vec(request).map_err(|_| AdminError::Api(ApiError::Transport))?;
    let (status, reply) = signed_exchange(context, Method::POST, ADMIN_TOKENS_PATH, body)?;
    let reply = Zeroizing::new(reply);
    let created: CreatedBody = decoded(status, &reply)?;
    if admin_token_id(&created.secret) != Some(created.token.id.as_str()) {
        return Err(AdminError::Api(ApiError::BadResponse));
    }
    Ok(CreatedToken {
        token: created.token,
        secret: Secret::new(created.secret),
    })
}

pub fn list_tokens(context: &AdminContext<'_>) -> Result<TokenList, AdminError> {
    let (status, reply) = signed_exchange(context, Method::GET, ADMIN_TOKENS_PATH, Vec::new())?;
    decoded(status, &reply)
}

pub fn revoke_token(context: &AdminContext<'_>, id: &str) -> Result<(), AdminError> {
    if !is_admin_token_id(id) {
        return Err(AdminError::UnknownToken);
    }
    let path = admin_token_path(id);
    let (status, reply) = signed_exchange(context, Method::DELETE, &path, Vec::new())?;
    match status {
        200..=299 => Ok(()),
        NOT_FOUND => Err(AdminError::UnknownToken),
        _ => Err(refusal(status, &reply)),
    }
}

pub fn token_whoami(server: &ServerUrl, token: &Secret) -> Result<TokenIdentity, AdminError> {
    let client = ApiClient::new(server).map_err(AdminError::Api)?;
    let (status, reply) = client
        .exchange_with_token(ADMIN_WHOAMI_PATH, token)
        .map_err(AdminError::Api)?;
    if status == UNAUTHORIZED {
        return Err(AdminError::TokenRefused);
    }
    decoded::<TokenWhoami>(status, &reply).map(|whoami| whoami.token)
}

fn signed_get<T: DeserializeOwned>(
    context: &AdminContext<'_>,
    client: &ApiClient,
    path: &str,
) -> Result<T, AdminError> {
    let (target, signed) = sign_for(context, client, "GET", path, b"")?;
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

fn listed(values: &[String]) -> String {
    if values.is_empty() {
        NONE_SHOWN.to_owned()
    } else {
        printable(&values.join(", "))
    }
}

pub fn render_token_identity(identity: &TokenIdentity) -> String {
    format!(
        "Token:   {} ({})\nScope:   {}\nRights:  {}\nExpires: {}",
        printable(&identity.name),
        printable(&identity.id),
        listed(&identity.scope),
        listed(&identity.rights),
        format_local(identity.expires_at)
    )
}

pub fn render_created(created: &CreatedToken) -> String {
    let token = &created.token;
    format!(
        "Created token {} ({}) with scope {}, expiring {}.\nThe secret below is shown only this once: store it now.",
        printable(&token.name),
        printable(&token.id),
        listed(&token.scope),
        format_local(token.expires_at)
    )
}

fn state_of(token: &TokenSummary, now: i64) -> &'static str {
    if token.revoked_at.is_some() {
        "revoked"
    } else if token.expires_at <= now {
        "expired"
    } else {
        "live"
    }
}

pub fn render_token_list(list: &TokenList, now: i64) -> String {
    if list.tokens.is_empty() {
        return "No tokens.".to_owned();
    }
    let mut lines =
        vec!["ID\tNAME\tSTATE\tSCOPE\tNETWORKS\tEXPIRES\tLAST USED\tCREATOR".to_owned()];
    for token in &list.tokens {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            printable(&token.id),
            printable(&token.name),
            state_of(token, now),
            listed(&token.scope),
            listed(&token.cidrs),
            format_local(token.expires_at),
            token
                .last_used_at
                .map_or_else(|| NONE_SHOWN.to_owned(), format_local),
            printable(&token.creator)
        ));
    }
    if list.truncated {
        lines.push(TRUNCATED_NOTE.to_owned());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::Duration;

    use jaunt_policy::AdminPermission;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    use super::{
        AdminError, AdminIdentity, MAX_TOKEN_FILE_BYTES, TokenList, TokenSource, TokenSummary,
        choose_signer, parse_scope, parse_token_source, parse_ttl, read_admin_token,
        render_identity, render_token_list,
    };

    const TOKEN: &str = "jat_AbC-_09xyzQ_s3cr3t-s3cr3t_s3cr3t-s3cr3t_s3cr3t-s3cr3t_Z";

    #[test]
    fn lifetimes_take_a_unit_and_stay_between_a_minute_and_ninety_days() {
        for (text, secs) in [
            ("60", Ok(60)),
            ("60s", Ok(60)),
            ("15m", Ok(900)),
            ("12h", Ok(43_200)),
            ("30d", Ok(2_592_000)),
            ("90d", Ok(7_776_000)),
        ] {
            assert_eq!(parse_ttl(text), secs, "{text}");
        }
        for bad in [
            "59",
            "91d",
            "",
            "d",
            "1w",
            "-5m",
            "1.5h",
            "99999999999999d",
            "3 d",
        ] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn scopes_are_admin_rights_other_than_tokens_write() {
        assert_eq!(parse_scope("audit.read"), Ok(AdminPermission::AuditRead));
        assert!(parse_scope("tokens.write").unwrap_err().contains("never"));
        assert!(parse_scope("ssh").is_err());
    }

    #[test]
    fn the_token_comes_from_a_file_or_the_environment_and_never_from_the_argument() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, format!("{TOKEN}\n")).unwrap();
        let from_file = read_admin_token(&TokenSource::File(file), None).unwrap();
        assert_eq!(from_file.expose(), TOKEN);
        let from_env = read_admin_token(&TokenSource::Env, Some(OsString::from(TOKEN))).unwrap();
        assert_eq!(from_env.expose(), TOKEN);
        assert_eq!(parse_token_source("env"), Ok(TokenSource::Env));
        assert!(parse_token_source("").is_err());

        let given = parse_token_source(TOKEN).unwrap();
        let refused = read_admin_token(&given, Some(OsString::from(TOKEN))).unwrap_err();
        assert!(matches!(refused, AdminError::TokenOnCommandLine));
        assert!(!refused.to_string().contains(&TOKEN[16..]));
        assert!(refused.to_string().contains("./NAME"));
        let token_named = dir.path().join(TOKEN);
        std::fs::write(&token_named, TOKEN).unwrap();
        let by_path = read_admin_token(&TokenSource::File(token_named), None).unwrap();
        assert_eq!(by_path.expose(), TOKEN);
        let notes = dir.path().join("jat_notes");
        std::fs::write(&notes, TOKEN).unwrap();
        assert!(
            read_admin_token(&parse_token_source(notes.to_str().unwrap()).unwrap(), None).is_ok()
        );

        for (source, env, expected) in [
            (TokenSource::Env, None, "is not set"),
            (TokenSource::Env, Some(OsString::from("jat_short")), "form"),
            (
                TokenSource::File(dir.path().join("missing")),
                None,
                "cannot read",
            ),
        ] {
            let err = read_admin_token(&source, env).unwrap_err();
            assert!(err.to_string().contains(expected), "{err}");
        }
        let large = dir.path().join("large");
        std::fs::write(
            &large,
            " ".repeat(usize::try_from(MAX_TOKEN_FILE_BYTES).unwrap() + 1),
        )
        .unwrap();
        assert!(matches!(
            read_admin_token(&TokenSource::File(large), None),
            Err(AdminError::TokenMalformed)
        ));
        let other = dir.path().join("other");
        std::fs::write(&other, format!("{TOKEN}x")).unwrap();
        let err = read_admin_token(&TokenSource::File(PathBuf::from(&other)), None).unwrap_err();
        assert!(!err.to_string().contains(&TOKEN[16..]));
    }

    #[test]
    fn the_token_list_shows_state_and_never_terminal_controls() {
        let token = |id: &str, revoked_at: Option<i64>, expires_at: i64| TokenSummary {
            id: id.to_owned(),
            name: "ci\u{1b}[2J".to_owned(),
            creator: "u-1".to_owned(),
            scope: vec!["audit.read".to_owned()],
            cidrs: Vec::new(),
            created_at: 0,
            expires_at,
            revoked_at,
            last_used_at: None,
        };
        let text = render_token_list(
            &TokenList {
                tokens: vec![
                    token("live", None, 200),
                    token("gone", Some(50), 200),
                    token("old", None, 100),
                ],
                truncated: false,
            },
            100,
        );
        assert!(!text.contains('\u{1b}'));
        let states: Vec<&str> = text
            .lines()
            .skip(1)
            .map(|line| line.split('\t').nth(2).unwrap())
            .collect();
        assert_eq!(states, ["live", "revoked", "expired"]);
        assert_eq!(
            render_token_list(
                &TokenList {
                    tokens: Vec::new(),
                    truncated: false
                },
                0
            ),
            "No tokens."
        );
        let cut = render_token_list(
            &TokenList {
                tokens: vec![token("live", None, 200)],
                truncated: true,
            },
            100,
        );
        assert!(
            cut.lines()
                .last()
                .unwrap()
                .starts_with("Only part of the list")
        );
        assert!(!text.contains("Only part of the list"));
    }
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
