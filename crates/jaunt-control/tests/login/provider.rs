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
use jaunt_oidc::{ClientSecret, OidcClient, OidcConfig};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

pub const CLIENT_ID: &str = "jaunt-test-client";
pub const CLIENT_SECRET: &str = "s3cr3t-value-for-tests";
pub const REDIRECT_URL: &str = "https://jaunt.example/v1/login/callback";

const ED_KEY_DER: &[u8] = include_bytes!("fixtures/test_only_ed1_private.der");
const JWKS: &str = r#"{"keys":[{"kty":"OKP","use":"sig","alg":"EdDSA","kid":"ed-1","crv":"Ed25519","x":"c7-MOCAr_ZcQncwLkiTMbqxxkfs1GQbWBnw0CSvsjRE"}]}"#;

#[derive(Clone)]
pub struct Identity {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
}

impl Identity {
    pub fn alice() -> Identity {
        Identity {
            subject: "user-1".to_owned(),
            email: "alice@example.com".to_owned(),
            email_verified: true,
        }
    }
}

struct Grant {
    challenge: String,
    nonce: String,
    redirect_uri: String,
    identity: Identity,
}

struct Shared {
    base: String,
    grants: Mutex<HashMap<String, Grant>>,
    next_code: AtomicUsize,
    on_token: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

pub struct FakeProvider {
    pub base: String,
    shared: Arc<Shared>,
}

impl FakeProvider {
    pub async fn start() -> FakeProvider {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let shared = Arc::new(Shared {
            base: base.clone(),
            grants: Mutex::new(HashMap::new()),
            next_code: AtomicUsize::new(0),
            on_token: Mutex::new(None),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(shared.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeProvider { base, shared }
    }

    pub async fn oidc_client(&self) -> OidcClient {
        let config = OidcConfig::new(
            self.base.clone(),
            CLIENT_ID,
            ClientSecret::new(CLIENT_SECRET),
            REDIRECT_URL,
        );
        OidcClient::discover(config).await.unwrap()
    }

    pub fn on_token(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.shared.on_token.lock().unwrap() = Some(Box::new(hook));
    }

    pub fn grant(&self, authorize_url: &str, identity: Identity) -> String {
        let (location, query) = authorize_url.split_once('?').unwrap();
        assert_eq!(location, format!("{}/authorize", self.base));
        let query: HashMap<String, String> = form_pairs(query);
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["redirect_uri"], REDIRECT_URL);
        assert_eq!(query["code_challenge_method"], "S256");
        let code = format!(
            "code-{}",
            self.shared.next_code.fetch_add(1, Ordering::SeqCst)
        );
        self.shared.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                challenge: query["code_challenge"].clone(),
                nonce: query["nonce"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                identity,
            },
        );
        code
    }
}

pub fn form_pairs(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

async fn discovery(State(shared): State<Arc<Shared>>) -> Json<Value> {
    let base = &shared.base;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

async fn jwks() -> Response {
    ([(header::CONTENT_TYPE, "application/json")], JWKS).into_response()
}

fn oauth_error(error: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))).into_response()
}

fn client_authenticated(headers: &HeaderMap, form: &HashMap<String, String>) -> bool {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| STANDARD.decode(value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    match basic {
        Some(pair) => pair == format!("{CLIENT_ID}:{CLIENT_SECRET}"),
        None => {
            form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
        }
    }
}

async fn token(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !client_authenticated(&headers, &form) {
        return oauth_error("invalid_client");
    }
    let field = |name: &str| form.get(name).map(String::as_str);
    if field("grant_type") != Some("authorization_code") {
        return oauth_error("invalid_request");
    }
    let grant = field("code").and_then(|code| shared.grants.lock().unwrap().remove(code));
    let Some(grant) = grant else {
        return oauth_error("invalid_grant");
    };
    let challenge = field("code_verifier")
        .map(|verifier| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
    if challenge.as_deref() != Some(grant.challenge.as_str())
        || field("redirect_uri") != Some(grant.redirect_uri.as_str())
    {
        return oauth_error("invalid_grant");
    }
    if let Some(hook) = shared.on_token.lock().unwrap().as_ref() {
        hook();
    }
    Json(json!({
        "access_token": "access-token-for-tests",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": mint_id_token(&shared, &grant),
    }))
    .into_response()
}

fn mint_id_token(shared: &Shared, grant: &Grant) -> String {
    let issued = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let identity = &grant.identity;
    let mut claims = Map::new();
    claims.insert("iss".into(), json!(shared.base));
    claims.insert("aud".into(), json!(CLIENT_ID));
    claims.insert("sub".into(), json!(identity.subject));
    claims.insert("exp".into(), json!(issued + 300));
    claims.insert("iat".into(), json!(issued));
    claims.insert("nonce".into(), json!(grant.nonce));
    claims.insert("email".into(), json!(identity.email));
    claims.insert("email_verified".into(), json!(identity.email_verified));
    claims.insert("preferred_username".into(), json!("alice"));
    claims.insert("name".into(), json!("Alice Example"));
    claims.insert("groups".into(), json!(["dev", "ops"]));
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed-1".to_owned());
    jsonwebtoken::encode(&header, &claims, &EncodingKey::from_ed_der(ED_KEY_DER)).unwrap()
}
