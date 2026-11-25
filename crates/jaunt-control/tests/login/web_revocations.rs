use axum::http::{Method, StatusCode};
use jaunt_store::NewUser;
use serde_json::{Value, json};

use crate::support::{DEFAULT_PEER, Harness, PUBLIC_ORIGIN, Reply};
use crate::web_support::{WebSignedIn, bob};

const REVOCATIONS: &str = "/v1/admin/revocations";

const ROLES: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: revokers }
spec:
  members: { users: [alice@example.com] }
  admin: [revocations.write, sessions.read]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: readers }
spec:
  members: { users: [bob@example.com] }
  admin: [sessions.read]
";

enum Csrf {
    Without,
    With,
}

impl Harness {
    async fn revocations_call(
        &self,
        method: Method,
        path: &str,
        signed: Option<&WebSignedIn>,
        csrf: Csrf,
        body: Option<(&str, Vec<u8>)>,
    ) -> Reply {
        let cookie = signed.map(WebSignedIn::cookie);
        let token = match (signed, csrf) {
            (Some(signed), Csrf::With) => Some(self.csrf_token(signed).await),
            _ => None,
        };
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(cookie) = &cookie {
            headers.push(("cookie", cookie));
        }
        if let Some(token) = &token {
            headers.push(("x-jaunt-csrf", token));
            headers.push(("origin", PUBLIC_ORIGIN));
        }
        self.request_as(method, path, DEFAULT_PEER, &headers, body)
            .await
    }

    async fn revoke_json(&self, signed: &WebSignedIn, body: &Value) -> Reply {
        self.revocations_call(
            Method::POST,
            REVOCATIONS,
            Some(signed),
            Csrf::With,
            Some(("application/json", serde_json::to_vec(body).unwrap())),
        )
        .await
    }

    async fn stored_user(&self, subject: &str) -> String {
        self.store
            .users()
            .upsert(
                &NewUser {
                    issuer: "https://idp.example".to_owned(),
                    subject: subject.to_owned(),
                    email: format!("{subject}@example.com"),
                    username: subject.to_owned(),
                    display_name: None,
                    groups: Vec::new(),
                },
                self.clock.now_secs(),
            )
            .await
            .unwrap()
            .id
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revocations_need_a_session_a_csrf_token_and_the_right_permission() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let carol = harness.stored_user("carol").await;
    let body = json!({"kind": "user", "subject": carol, "reason": "left"});
    let json_body = || Some(("application/json", serde_json::to_vec(&body).unwrap()));
    let item = format!("{REVOCATIONS}/67e55044-10b1-426f-9247-bb680e5fe0c8");

    for (method, path, body) in [
        (Method::GET, REVOCATIONS, None),
        (Method::POST, REVOCATIONS, json_body()),
        (Method::DELETE, item.as_str(), None),
    ] {
        let reply = harness
            .revocations_call(method.clone(), path, None, Csrf::Without, body)
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method}");
    }

    let alice = harness.web_sign_in().await;
    let no_csrf = harness
        .revocations_call(
            Method::POST,
            REVOCATIONS,
            Some(&alice),
            Csrf::Without,
            json_body(),
        )
        .await;
    assert_eq!(no_csrf.status, StatusCode::FORBIDDEN);
    let no_csrf_delete = harness
        .revocations_call(Method::DELETE, &item, Some(&alice), Csrf::Without, None)
        .await;
    assert_eq!(no_csrf_delete.status, StatusCode::FORBIDDEN);

    let reader = harness.web_sign_in_with("", bob()).await;
    let listed = harness
        .revocations_call(Method::GET, REVOCATIONS, Some(&reader), Csrf::Without, None)
        .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.text());
    let refused = harness.revoke_json(&reader, &body).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json(), json!({"error": "forbidden"}));
    let refused_delete = harness
        .revocations_call(Method::DELETE, &item, Some(&reader), Csrf::With, None)
        .await;
    assert_eq!(refused_delete.status, StatusCode::FORBIDDEN);
    assert!(
        harness
            .store
            .revocations()
            .page(None, 10)
            .await
            .unwrap()
            .revocations
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_administrator_revokes_lists_and_removes_a_revocation() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let carol = harness.stored_user("carol").await;
    let dave = harness.stored_user("dave").await;
    let alice = harness.web_sign_in().await;
    let body = json!({"kind": "user", "subject": carol, "reason": "left the company"});

    let created = harness.revoke_json(&alice, &body).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    let created = created.json();
    assert_eq!(created["created"], true);
    assert_eq!(created["terminated_sessions"], 0);
    let revocation = &created["revocation"];
    assert_eq!(revocation["kind"], "user");
    assert_eq!(revocation["subject"], carol.as_str());
    assert_eq!(revocation["reason"], "left the company");
    let session = harness
        .web_get("/v1/web/session", Some(&alice.cookie()))
        .await
        .json();
    assert_eq!(
        revocation["created_by"],
        format!("web:{}", session["user_id"].as_str().unwrap())
    );
    let id = revocation["id"].as_str().unwrap().to_owned();

    let repeated = harness.revoke_json(&alice, &body).await;
    assert_eq!(repeated.status, StatusCode::OK);
    assert_eq!(repeated.json()["created"], false);
    assert_eq!(repeated.json()["revocation"]["id"], id.as_str());
    harness
        .revoke_json(
            &alice,
            &json!({"kind": "user", "subject": dave, "reason": "second"}),
        )
        .await;

    let first_page = harness
        .revocations_call(
            Method::GET,
            &format!("{REVOCATIONS}?limit=1"),
            Some(&alice),
            Csrf::Without,
            None,
        )
        .await;
    assert_eq!(first_page.status, StatusCode::OK, "{}", first_page.text());
    let first_page = first_page.json();
    assert_eq!(first_page["revocations"].as_array().unwrap().len(), 1);
    let next = first_page["next"].as_str().unwrap().to_owned();
    let second_page = harness
        .revocations_call(
            Method::GET,
            &format!("{REVOCATIONS}?limit=1&after={next}"),
            Some(&alice),
            Csrf::Without,
            None,
        )
        .await
        .json();
    assert_eq!(second_page["revocations"].as_array().unwrap().len(), 1);
    assert_eq!(second_page["next"], Value::Null);
    let mut subjects = vec![
        first_page["revocations"][0]["subject"].clone(),
        second_page["revocations"][0]["subject"].clone(),
    ];
    subjects.sort_by_key(|value| value.as_str().unwrap().to_owned());
    let mut expected = vec![json!(carol), json!(dave)];
    expected.sort_by_key(|value| value.as_str().unwrap().to_owned());
    assert_eq!(subjects, expected);

    let path = format!("{REVOCATIONS}/{id}");
    let removed = harness
        .revocations_call(Method::DELETE, &path, Some(&alice), Csrf::With, None)
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{}", removed.text());
    let again = harness
        .revocations_call(Method::DELETE, &path, Some(&alice), Csrf::With, None)
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.json(), json!({"error": "not_found"}));
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_and_unknown_subjects_are_refused() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let carol = harness.stored_user("carol").await;
    let alice = harness.web_sign_in().await;

    for (body, status, code) in [
        (
            json!({"kind": "user", "subject": carol, "reason": "r", "extra": 1}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "group", "subject": carol, "reason": "r"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "user", "subject": "a b", "reason": "r"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "serial", "subject": "01", "reason": "r"}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "user", "subject": carol, "reason": ""}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "user", "subject": carol}),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            json!({"kind": "user", "subject": "nobody", "reason": "r"}),
            StatusCode::NOT_FOUND,
            "unknown_subject",
        ),
        (
            json!({"kind": "serial", "subject": "12345", "reason": "r"}),
            StatusCode::NOT_FOUND,
            "unknown_subject",
        ),
        (
            json!({"kind": "node", "subject": "no-such-node", "reason": "r"}),
            StatusCode::NOT_FOUND,
            "unknown_subject",
        ),
    ] {
        let reply = harness.revoke_json(&alice, &body).await;
        assert_eq!(reply.status, status, "{body}");
        assert_eq!(reply.error_code(), code, "{body}");
    }
    let wrong_type = harness
        .revocations_call(
            Method::POST,
            REVOCATIONS,
            Some(&alice),
            Csrf::With,
            Some(("text/plain", b"{}".to_vec())),
        )
        .await;
    assert_eq!(wrong_type.status, StatusCode::BAD_REQUEST);
    for query in [
        "limit=0",
        "limit=201",
        "after=junk",
        "limit=1&limit=2",
        "x=1",
    ] {
        let reply = harness
            .revocations_call(
                Method::GET,
                &format!("{REVOCATIONS}?{query}"),
                Some(&alice),
                Csrf::Without,
                None,
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
    }
    assert!(
        harness
            .store
            .revocations()
            .page(None, 10)
            .await
            .unwrap()
            .revocations
            .is_empty()
    );
}
