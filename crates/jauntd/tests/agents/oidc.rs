use axum::Router;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use jaunt_oidc::{ClientSecret, OidcClient, OidcConfig};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub struct FakeDiscovery {
    base: String,
    serve: JoinHandle<()>,
}

impl FakeDiscovery {
    pub async fn start() -> FakeDiscovery {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let metadata = json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
        })
        .to_string();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move {
                    ([(header::CONTENT_TYPE, "application/json")], metadata).into_response()
                }),
            )
            .route(
                "/jwks",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        r#"{"keys":[]}"#,
                    )
                        .into_response()
                }),
            );
        let serve = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        FakeDiscovery { base, serve }
    }

    pub async fn client(&self) -> OidcClient {
        let config = OidcConfig::new(
            self.base.clone(),
            "jaunt-test-client",
            ClientSecret::new("client-secret-for-tests"),
            "https://jaunt.example.test/v1/login/callback",
        );
        OidcClient::discover(config).await.unwrap()
    }
}

impl Drop for FakeDiscovery {
    fn drop(&mut self) {
        self.serve.abort();
    }
}
