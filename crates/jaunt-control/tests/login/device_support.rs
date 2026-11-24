use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

use crate::provider::{Identity, form_pairs};
use crate::support::{DEFAULT_PEER, Harness, Reply, challenge_for};

pub const FORM: &str = "application/x-www-form-urlencoded";

pub struct DeviceSession {
    pub login_id: String,
    pub verifier: String,
    pub user_code: String,
    pub body: Value,
}

pub struct Continued {
    pub reply: Reply,
    pub continue_token: String,
    pub authorize_url: String,
    pub state: String,
    pub cookie: String,
}

pub struct ApprovalPage {
    pub reply: Reply,
    pub token: String,
}

pub fn hidden_field(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no hidden field {name} in {html}"))
        + marker.len();
    let length = html[start..].find('"').unwrap();
    html[start..start + length].to_owned()
}

fn form_body(fields: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

impl Harness {
    pub async fn request_as(
        &self,
        method: Method,
        path: &str,
        peer: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, Vec<u8>)>,
    ) -> Reply {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let body = match body {
            Some((content_type, bytes)) => {
                builder = builder.header(header::CONTENT_TYPE, content_type);
                Body::from(bytes)
            }
            None => Body::empty(),
        };
        let mut request = builder.body(body).unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        self.send(request).await
    }

    pub async fn post_form_as(
        &self,
        path: &str,
        peer: &str,
        headers: &[(&str, &str)],
        fields: &[(&str, &str)],
    ) -> Reply {
        self.request_as(
            Method::POST,
            path,
            peer,
            headers,
            Some((FORM, form_body(fields).into_bytes())),
        )
        .await
    }

    pub async fn post_form(&self, path: &str, fields: &[(&str, &str)]) -> Reply {
        self.post_form_as(path, DEFAULT_PEER, &[], fields).await
    }

    pub async fn device_start_as(
        &self,
        label: Option<&str>,
        peer: &str,
        headers: &[(&str, &str)],
    ) -> DeviceSession {
        let verifier = self.next_verifier();
        let mut body = json!({
            "code_challenge": challenge_for(&verifier),
            "code_challenge_method": "S256",
        });
        if let Some(label) = label {
            body["client_label"] = json!(label);
        }
        let reply = self
            .request_as(
                Method::POST,
                "/v1/login/device/start",
                peer,
                headers,
                Some(("application/json", serde_json::to_vec(&body).unwrap())),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let body = reply.json();
        DeviceSession {
            login_id: body["login_id"].as_str().unwrap().to_owned(),
            verifier,
            user_code: body["user_code"].as_str().unwrap().to_owned(),
            body,
        }
    }

    pub async fn device_start(&self) -> DeviceSession {
        self.device_start_as(Some("build host"), DEFAULT_PEER, &[])
            .await
    }

    pub async fn enter_code_as(&self, code: &str, peer: &str, headers: &[(&str, &str)]) -> Reply {
        self.post_form_as("/login/device", peer, headers, &[("user_code", code)])
            .await
    }

    pub async fn enter_code(&self, code: &str) -> Reply {
        self.enter_code_as(code, DEFAULT_PEER, &[]).await
    }

    pub async fn confirmation_token(&self, session: &DeviceSession) -> String {
        let reply = self.enter_code(&session.user_code).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let html = reply.text();
        assert_eq!(hidden_field(&html, "login_id"), session.login_id);
        hidden_field(&html, "token")
    }

    pub async fn proceed(&self, login_id: &str, token: &str) -> Reply {
        self.post_form(
            "/login/device/continue",
            &[("login_id", login_id), ("token", token)],
        )
        .await
    }

    pub async fn continue_flow(&self, session: &DeviceSession) -> Continued {
        let continue_token = self.confirmation_token(session).await;
        let reply = self.proceed(&session.login_id, &continue_token).await;
        let authorize_url = reply.refresh_target();
        let state = form_pairs(authorize_url.split_once('?').unwrap().1)["state"].clone();
        let cookies = reply.set_cookies();
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        let cookie = cookies[0].split(';').next().unwrap().to_owned();
        Continued {
            reply,
            continue_token,
            authorize_url,
            state,
            cookie,
        }
    }

    pub async fn provider_callback(
        &self,
        continued: &Continued,
        identity: Identity,
        cookie: Option<&str>,
    ) -> Reply {
        let code = self.provider.grant(&continued.authorize_url, identity);
        let uri = format!("/v1/login/callback?code={code}&state={}", continued.state);
        match cookie {
            Some(cookie) => self.get_with_headers(&uri, &[("cookie", cookie)]).await,
            None => self.get(&uri).await,
        }
    }

    pub async fn sign_in_as(&self, session: &DeviceSession, identity: Identity) -> ApprovalPage {
        let continued = self.continue_flow(session).await;
        let reply = self
            .provider_callback(&continued, identity, Some(&continued.cookie))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let token = hidden_field(&reply.text(), "token");
        ApprovalPage { reply, token }
    }

    pub async fn sign_in(&self, session: &DeviceSession) -> ApprovalPage {
        self.sign_in_as(session, Identity::alice()).await
    }

    pub async fn approve_device(&self, login_id: &str, token: &str) -> Reply {
        self.post_form(
            "/login/device/approve",
            &[("login_id", login_id), ("token", token)],
        )
        .await
    }

    pub async fn deny_device(&self, login_id: &str, token: &str) -> Reply {
        self.post_form(
            "/login/device/deny",
            &[("login_id", login_id), ("token", token)],
        )
        .await
    }

    pub async fn poll_raw(&self, body: &Value) -> Reply {
        self.post_json("/v1/login/device/poll", body).await
    }

    pub async fn poll_with(&self, login_id: &str, verifier: &str, public_key: &str) -> Reply {
        self.poll_raw(&json!({
            "login_id": login_id,
            "code_verifier": verifier,
            "public_key": public_key,
        }))
        .await
    }

    pub async fn poll(&self, session: &DeviceSession, public_key: &str) -> Reply {
        self.poll_with(&session.login_id, &session.verifier, public_key)
            .await
    }
}
