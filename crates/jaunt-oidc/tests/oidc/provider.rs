use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnectionBuilder;
use hyper_util::service::TowerToHyperService;
use jaunt_oidc::{ClientSecret, OidcClient, OidcConfig, OidcError, OidcIdentity, PendingAuth};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openidconnect::url::Url;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub const CLIENT_ID: &str = "jaunt-test-client";
pub const CLIENT_SECRET: &str = "s3cr3t-value-for-tests";
pub const REDIRECT_URL: &str = "http://127.0.0.1:8085/callback";
pub const ACCESS_TOKEN: &str = "access-token-for-tests";

const RSA1_DER: &[u8] = include_bytes!("fixtures/test_only_rsa1_private.der");
const RSA2_DER: &[u8] = include_bytes!("fixtures/test_only_rsa2_private.der");
const EC1_DER: &[u8] = include_bytes!("fixtures/test_only_ec1_private.der");
const ED1_DER: &[u8] = include_bytes!("fixtures/test_only_ed1_private.der");
const PUBLIC_JWKS: &str = include_str!("fixtures/public_jwks.json");

pub fn now() -> i64 {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    i64::try_from(elapsed.as_secs()).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    Rsa,
    Ec,
    Ed,
    ForeignRsaWithKnownKid,
    RotatedRsa,
    Hs256WithClientSecret,
    Unsigned,
}

#[derive(Clone)]
pub struct TokenSpec {
    signer: Signer,
    edits: Vec<(String, Value)>,
}

impl Default for TokenSpec {
    fn default() -> Self {
        Self {
            signer: Signer::Rsa,
            edits: Vec::new(),
        }
    }
}

impl TokenSpec {
    pub fn signer(mut self, signer: Signer) -> Self {
        self.signer = signer;
        self
    }

    pub fn set(mut self, claim: &str, value: Value) -> Self {
        self.edits.push((claim.to_owned(), value));
        self
    }

    pub fn remove(self, claim: &str) -> Self {
        self.set(claim, Value::Null)
    }
}

struct Grant {
    challenge: String,
    nonce: String,
    spec: TokenSpec,
}

struct Shared {
    base: String,
    metadata: Mutex<Map<String, Value>>,
    published_keys: Mutex<Vec<&'static str>>,
    userinfo: Mutex<Option<Value>>,
    grants: Mutex<HashMap<String, Grant>>,
    last_auth_method: Mutex<Option<&'static str>>,
    token_redirect: Mutex<Option<String>>,
    jwks_hits: AtomicUsize,
    token_hits: AtomicUsize,
    userinfo_hits: AtomicUsize,
    next_code: AtomicUsize,
}

pub struct FakeProvider {
    pub base: String,
    root_certificate_pem: Option<String>,
    shared: Arc<Shared>,
}

impl FakeProvider {
    pub async fn start() -> Self {
        Self::spawn(false).await
    }

    pub async fn start_tls() -> Self {
        Self::spawn(true).await
    }

    async fn spawn(tls: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let scheme = if tls { "https" } else { "http" };
        let base = format!(
            "{scheme}://127.0.0.1:{}",
            listener.local_addr().unwrap().port()
        );
        let metadata = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code", "id_token", "code id_token"],
            "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "EdDSA"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        });
        let Value::Object(metadata) = metadata else {
            unreachable!()
        };
        let shared = Arc::new(Shared {
            base: base.clone(),
            metadata: Mutex::new(metadata),
            published_keys: Mutex::new(vec!["rsa1", "ec1", "ed1"]),
            userinfo: Mutex::new(None),
            grants: Mutex::new(HashMap::new()),
            last_auth_method: Mutex::new(None),
            token_redirect: Mutex::new(None),
            jwks_hits: AtomicUsize::new(0),
            token_hits: AtomicUsize::new(0),
            userinfo_hits: AtomicUsize::new(0),
            next_code: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(shared.clone());
        let root_certificate_pem = if tls {
            Some(serve_tls(listener, app))
        } else {
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            None
        };
        Self {
            base,
            root_certificate_pem,
            shared,
        }
    }

    pub fn redirect_token_endpoint_to(&self, location: String) {
        *self.shared.token_redirect.lock().unwrap() = Some(location);
    }

    pub fn set_metadata(&self, key: &str, value: Value) {
        self.shared
            .metadata
            .lock()
            .unwrap()
            .insert(key.to_owned(), value);
    }

    pub fn enable_userinfo(&self, claims: Value) {
        self.set_metadata(
            "userinfo_endpoint",
            json!(format!("{}/userinfo", self.base)),
        );
        *self.shared.userinfo.lock().unwrap() = Some(claims);
    }

    pub fn publish_key(&self, name: &'static str) {
        self.shared.published_keys.lock().unwrap().push(name);
    }

    pub fn jwks_hits(&self) -> usize {
        self.shared.jwks_hits.load(Ordering::SeqCst)
    }

    pub fn token_hits(&self) -> usize {
        self.shared.token_hits.load(Ordering::SeqCst)
    }

    pub fn userinfo_hits(&self) -> usize {
        self.shared.userinfo_hits.load(Ordering::SeqCst)
    }

    pub fn last_auth_method(&self) -> Option<&'static str> {
        *self.shared.last_auth_method.lock().unwrap()
    }

    pub fn config(&self) -> OidcConfig {
        let mut config = self.config_without_root();
        config.extra_root_certificates_pem = self.root_certificate_pem.iter().cloned().collect();
        config
    }

    pub fn config_without_root(&self) -> OidcConfig {
        OidcConfig::new(
            self.base.clone(),
            CLIENT_ID,
            ClientSecret::new(CLIENT_SECRET),
            REDIRECT_URL,
        )
    }

    pub fn root_certificate_pem(&self) -> String {
        self.root_certificate_pem.clone().unwrap()
    }

    pub async fn client(&self) -> OidcClient {
        OidcClient::discover(self.config()).await.unwrap()
    }

    pub fn grant(&self, pending: &PendingAuth, spec: TokenSpec) -> String {
        let url = Url::parse(&pending.authorize_url).unwrap();
        assert_eq!(
            url.as_str().split('?').next().unwrap(),
            format!("{}/authorize", self.base)
        );
        let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["redirect_uri"], REDIRECT_URL);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["state"], pending.state);
        let code = format!(
            "code-{}",
            self.shared.next_code.fetch_add(1, Ordering::SeqCst)
        );
        self.shared.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                challenge: query["code_challenge"].clone(),
                nonce: query["nonce"].clone(),
                spec,
            },
        );
        code
    }

    pub async fn login(
        &self,
        client: &OidcClient,
        spec: TokenSpec,
    ) -> Result<OidcIdentity, OidcError> {
        let pending = client.begin();
        let code = self.grant(&pending, spec);
        let state = pending.state.clone();
        client.complete(pending, &code, &state).await
    }
}

fn serve_tls(listener: TcpListener, app: Router) -> String {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let certificate_pem = certified.cert.pem();
    let chain = vec![CertificateDer::from(certified.cert.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                ConnectionBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(app))
                    .await
                    .ok();
            });
        }
    });
    certificate_pem
}

async fn discovery(State(shared): State<Arc<Shared>>) -> Json<Value> {
    Json(Value::Object(shared.metadata.lock().unwrap().clone()))
}

async fn jwks(State(shared): State<Arc<Shared>>) -> Json<Value> {
    shared.jwks_hits.fetch_add(1, Ordering::SeqCst);
    let all: Map<String, Value> = serde_json::from_str(PUBLIC_JWKS).unwrap();
    let keys: Vec<Value> = shared
        .published_keys
        .lock()
        .unwrap()
        .iter()
        .map(|name| all[*name].clone())
        .collect();
    Json(json!({ "keys": keys }))
}

async fn token(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    shared.token_hits.fetch_add(1, Ordering::SeqCst);
    let redirect = shared.token_redirect.lock().unwrap().clone();
    if let Some(location) = redirect {
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [(header::LOCATION, location)],
        )
            .into_response();
    }
    if !client_authenticated(&shared, &headers, &form) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let field = |name: &str| form.get(name).map(String::as_str);
    if field("grant_type") != Some("authorization_code")
        || field("redirect_uri") != Some(REDIRECT_URL)
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let grant = field("code").and_then(|code| shared.grants.lock().unwrap().remove(code));
    let Some(grant) = grant else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let challenge = field("code_verifier")
        .map(|verifier| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
    if challenge.as_deref() != Some(grant.challenge.as_str()) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    Json(json!({
        "access_token": ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": mint_id_token(&shared, &grant),
    }))
    .into_response()
}

async fn userinfo(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    shared.userinfo_hits.fetch_add(1, Ordering::SeqCst);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    if bearer != Some(format!("Bearer {ACCESS_TOKEN}").as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match shared.userinfo.lock().unwrap().clone() {
        Some(claims) => Json(claims).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

fn client_authenticated(
    shared: &Shared,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> bool {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| STANDARD.decode(value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let (method, ok) = match basic {
        Some(pair) => ("basic", pair == format!("{CLIENT_ID}:{CLIENT_SECRET}")),
        None => (
            "post",
            form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET),
        ),
    };
    *shared.last_auth_method.lock().unwrap() = Some(method);
    ok
}

fn mint_id_token(shared: &Shared, grant: &Grant) -> String {
    let issued = now();
    let mut claims = Map::new();
    claims.insert("iss".into(), json!(shared.base));
    claims.insert("aud".into(), json!(CLIENT_ID));
    claims.insert("sub".into(), json!("user-1"));
    claims.insert("exp".into(), json!(issued + 300));
    claims.insert("iat".into(), json!(issued));
    claims.insert("nonce".into(), json!(grant.nonce));
    claims.insert("email".into(), json!("alice@example.com"));
    claims.insert("email_verified".into(), json!(true));
    claims.insert("preferred_username".into(), json!("alice"));
    claims.insert("name".into(), json!("Alice Example"));
    claims.insert("groups".into(), json!(["dev", "ops"]));
    for (claim, value) in &grant.spec.edits {
        if value.is_null() {
            claims.remove(claim);
        } else {
            claims.insert(claim.clone(), value.clone());
        }
    }
    sign(grant.spec.signer, &claims)
}

fn sign(signer: Signer, claims: &Map<String, Value>) -> String {
    let (algorithm, kid, key) = match signer {
        Signer::Rsa => (
            Algorithm::RS256,
            Some("rsa-1"),
            EncodingKey::from_rsa_der(RSA1_DER),
        ),
        Signer::Ec => (
            Algorithm::ES256,
            Some("ec-1"),
            EncodingKey::from_ec_der(EC1_DER),
        ),
        Signer::Ed => (
            Algorithm::EdDSA,
            Some("ed-1"),
            EncodingKey::from_ed_der(ED1_DER),
        ),
        Signer::ForeignRsaWithKnownKid => (
            Algorithm::RS256,
            Some("rsa-1"),
            EncodingKey::from_rsa_der(RSA2_DER),
        ),
        Signer::RotatedRsa => (
            Algorithm::RS256,
            Some("rsa-2"),
            EncodingKey::from_rsa_der(RSA2_DER),
        ),
        Signer::Hs256WithClientSecret => (
            Algorithm::HS256,
            None,
            EncodingKey::from_secret(CLIENT_SECRET.as_bytes()).unwrap(),
        ),
        Signer::Unsigned => {
            let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
            return format!("{header}.{payload}.");
        }
    };
    let mut header = Header::new(algorithm);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}
