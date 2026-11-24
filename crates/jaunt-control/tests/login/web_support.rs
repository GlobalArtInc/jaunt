use axum::http::{Method, StatusCode};
use jaunt_store::NewUser;

use crate::provider::{Identity, form_pairs};
use crate::support::{DEFAULT_PEER, Harness, Options, PUBLIC_ORIGIN, Reply};

pub const SESSION_COOKIE: &str = "__Host-jaunt";
pub const LOGIN_COOKIE: &str = "__Host-jaunt-web-login";
pub const SESSION_TTL_SECS: u64 = 28_800;
pub const BROWSER: &str = "jaunt-test-browser/1.0";

pub const APPROVER_AND_OPS_ROLES: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: approvers }
spec:
  members: { users: [alice@example.com] }
  admin: [nodes.approve, sessions.read, audit.read]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: approvers-without-audit }
spec:
  members: { users: [carol@example.com] }
  admin: [nodes.approve, sessions.read]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: ops-readers }
spec:
  members: { groups: [ops] }
  admin: [recordings.read]
";

pub const READERS_ONLY_ROLES: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: ops-readers }
spec:
  members: { groups: [ops] }
  admin: [recordings.read]
";

pub fn bob() -> Identity {
    Identity {
        subject: "user-2".to_owned(),
        email: "bob@example.com".to_owned(),
        email_verified: true,
        username: "bob".to_owned(),
    }
}

pub fn carol() -> Identity {
    Identity {
        subject: "user-3".to_owned(),
        email: "carol@example.com".to_owned(),
        email_verified: true,
        username: "carol".to_owned(),
    }
}

pub struct WebStart {
    pub reply: Reply,
    pub authorize_url: String,
    pub state: String,
    pub login_cookie: String,
}

pub struct WebSignedIn {
    pub reply: Reply,
    pub secret: String,
}

impl WebSignedIn {
    pub fn cookie(&self) -> String {
        format!("{SESSION_COOKIE}={}", self.secret)
    }
}

pub fn cookie_value(set_cookie: &str) -> &str {
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
}

impl Harness {
    pub async fn with_web() -> Harness {
        Harness::with(Options {
            web: true,
            ..Options::default()
        })
        .await
    }

    pub async fn web_request(
        &self,
        method: Method,
        path: &str,
        cookie: Option<&str>,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        if let Some(cookie) = cookie {
            all.push(("cookie", cookie));
        }
        self.request_as(method, path, DEFAULT_PEER, &all, None)
            .await
    }

    pub async fn web_get(&self, path: &str, cookie: Option<&str>) -> Reply {
        self.web_request(Method::GET, path, cookie, &[]).await
    }

    pub async fn web_start(&self, query: &str) -> WebStart {
        let reply = self.get(&format!("/v1/web/login{query}")).await;
        let authorize_url = reply.location().to_owned();
        let state = form_pairs(authorize_url.split_once('?').unwrap().1)["state"].clone();
        let cookies = reply.set_cookies();
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        let login_cookie = cookies[0].split(';').next().unwrap().to_owned();
        WebStart {
            reply,
            authorize_url,
            state,
            login_cookie,
        }
    }

    pub async fn web_callback(
        &self,
        start: &WebStart,
        identity: Identity,
        cookie: Option<&str>,
    ) -> Reply {
        let code = self.provider.grant(&start.authorize_url, identity);
        let uri = format!("/v1/login/callback?code={code}&state={}", start.state);
        let mut headers = vec![("user-agent", BROWSER)];
        if let Some(cookie) = cookie {
            headers.push(("cookie", cookie));
        }
        self.get_with_headers(&uri, &headers).await
    }

    pub async fn web_sign_in_with(&self, query: &str, identity: Identity) -> WebSignedIn {
        let start = self.web_start(query).await;
        let reply = self
            .web_callback(&start, identity, Some(&start.login_cookie))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let secret = reply
            .set_cookies()
            .iter()
            .find(|cookie| cookie.starts_with(&format!("{SESSION_COOKIE}=")))
            .map(|cookie| cookie_value(cookie).to_owned())
            .expect("no session cookie was issued");
        WebSignedIn { reply, secret }
    }

    pub async fn web_sign_in(&self) -> WebSignedIn {
        self.web_sign_in_with("", Identity::alice()).await
    }

    pub async fn csrf_token(&self, signed: &WebSignedIn) -> String {
        let reply = self
            .web_get("/v1/web/session", Some(&signed.cookie()))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        reply.json()["csrf_token"].as_str().unwrap().to_owned()
    }

    pub async fn web_post_with_csrf(&self, path: &str, signed: &WebSignedIn) -> Reply {
        let token = self.csrf_token(signed).await;
        self.web_request(
            Method::POST,
            path,
            Some(&signed.cookie()),
            &[("x-jaunt-csrf", &token), ("origin", PUBLIC_ORIGIN)],
        )
        .await
    }

    pub async fn assert_alice_was_never_stored(&self) {
        let probe_time = self.clock.now_secs() + 1_000;
        let probe = self
            .store
            .users()
            .upsert(
                &NewUser {
                    issuer: self.provider.base.clone(),
                    subject: "user-1".to_owned(),
                    email: "alice@example.com".to_owned(),
                    username: String::new(),
                    display_name: None,
                    groups: Vec::new(),
                },
                probe_time,
            )
            .await
            .unwrap();
        assert_eq!(probe.created_at, probe_time);
    }
}
