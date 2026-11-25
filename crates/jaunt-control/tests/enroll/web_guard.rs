use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::session_support::{LOGIN, NODE_NAME, authorize, holder, node, role, routed};
use crate::support::{Harness, Reply, sha256_hex};
use crate::web_support::{
    Admin, Csrf, Looked, admin, approve_with, call, delete, get, looked_up, lookup, reject_with,
    web_harness,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Needs {
    NodesApprove,
    SessionsRead,
}

struct Route {
    method: Method,
    path: String,
    needs: Needs,
    body: Option<Value>,
    allowed: StatusCode,
}

async fn send(harness: &Harness, route: &Route, who: Option<&Admin>, csrf: Csrf) -> Reply {
    call(
        harness,
        route.method.clone(),
        &route.path,
        who,
        csrf,
        route.body.as_ref(),
    )
    .await
}

#[tokio::test]
async fn every_admin_route_needs_a_session_its_permission_and_for_changes_csrf_and_origin() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let approver = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;
    let enrolment = harness.enroll("web-09").await;
    let enrolment_id = looked_up(&harness, &approver, &enrolment)
        .await
        .enrolment_id;
    let intent = json!({"intent": "A".repeat(43)});

    let routes = [
        Route {
            method: Method::GET,
            path: "/v1/admin/nodes".to_owned(),
            needs: Needs::NodesApprove,
            body: None,
            allowed: StatusCode::OK,
        },
        Route {
            method: Method::GET,
            path: format!("/v1/admin/nodes/{node_id}"),
            needs: Needs::NodesApprove,
            body: None,
            allowed: StatusCode::OK,
        },
        Route {
            method: Method::DELETE,
            path: format!("/v1/admin/nodes/{node_id}"),
            needs: Needs::NodesApprove,
            body: Some(json!({"confirm_name": "not-the-name"})),
            allowed: StatusCode::UNPROCESSABLE_ENTITY,
        },
        Route {
            method: Method::GET,
            path: format!("/v1/admin/nodes/{node_id}/access"),
            needs: Needs::SessionsRead,
            body: None,
            allowed: StatusCode::OK,
        },
        Route {
            method: Method::POST,
            path: "/v1/admin/enrolments/lookup".to_owned(),
            needs: Needs::NodesApprove,
            body: Some(json!({"code": "ZZZZ-ZZZZ"})),
            allowed: StatusCode::UNPROCESSABLE_ENTITY,
        },
        Route {
            method: Method::POST,
            path: format!("/v1/admin/enrolments/{enrolment_id}/approve"),
            needs: Needs::NodesApprove,
            body: Some(intent.clone()),
            allowed: StatusCode::UNPROCESSABLE_ENTITY,
        },
        Route {
            method: Method::POST,
            path: format!("/v1/admin/enrolments/{enrolment_id}/reject"),
            needs: Needs::NodesApprove,
            body: Some(intent),
            allowed: StatusCode::UNPROCESSABLE_ENTITY,
        },
        Route {
            method: Method::GET,
            path: "/v1/admin/sessions".to_owned(),
            needs: Needs::SessionsRead,
            body: None,
            allowed: StatusCode::OK,
        },
        Route {
            method: Method::GET,
            path: format!("/v1/admin/sessions/{session_id}"),
            needs: Needs::SessionsRead,
            body: None,
            allowed: StatusCode::OK,
        },
    ];

    for route in &routes {
        let (holder_of, stranger) = match route.needs {
            Needs::NodesApprove => (&approver, &reader),
            Needs::SessionsRead => (&reader, &approver),
        };
        let label = format!("{} {}", route.method, route.path);

        let anonymous = send(&harness, route, None, Csrf::Valid).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{label}");
        let refused = send(&harness, route, Some(stranger), Csrf::Valid).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(refused.json(), json!({"error": "forbidden"}), "{label}");
        if route.method != Method::GET {
            for csrf in [Csrf::Missing, Csrf::ForeignOrigin] {
                let refused = send(&harness, route, Some(holder_of), csrf).await;
                assert_eq!(refused.status, StatusCode::FORBIDDEN, "{label} {csrf:?}");
            }
        }
        let allowed = send(&harness, route, Some(holder_of), Csrf::Valid).await;
        assert_eq!(allowed.status, route.allowed, "{label}: {}", allowed.text());
        assert_eq!(allowed.headers["cache-control"], "no-store", "{label}");
        assert_eq!(
            allowed.headers["content-type"], "application/json",
            "{label}"
        );
    }
}

#[tokio::test]
async fn no_admin_response_or_refusal_carries_a_code_a_handle_a_cookie_a_csrf_token_or_an_intent() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let approver = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;
    let approved = harness.enroll("web-02").await;
    let rejected = harness.enroll("web-03").await;
    let waiting = harness.enroll("web-04").await;

    let mut lookups: Vec<(Reply, String)> = Vec::new();
    for enrolled in [&approved, &rejected] {
        let reply = lookup(&harness, &approver, &enrolled.code).await;
        assert_eq!(reply.status, StatusCode::OK);
        let intent = reply.json()["intent"].as_str().unwrap().to_owned();
        lookups.push((reply, intent));
    }
    let approve_looked = Looked {
        enrolment_id: lookups[0].0.json()["enrolment"]["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        intent: lookups[0].1.clone(),
    };
    let reject_looked = Looked {
        enrolment_id: lookups[1].0.json()["enrolment"]["id"]
            .as_str()
            .unwrap()
            .to_owned(),
        intent: lookups[1].1.clone(),
    };

    let node_path = format!("/v1/admin/nodes/{node_id}");
    let mut replies: Vec<Reply> = vec![
        lookup(&harness, &approver, "ZZZZ-ZZZZ").await,
        lookup(&harness, &reader, &waiting.code).await,
        approve_with(&harness, &approver, &approve_looked, None).await,
        approve_with(&harness, &approver, &approve_looked, None).await,
        reject_with(&harness, &approver, &reject_looked).await,
        reject_with(&harness, &approver, &reject_looked).await,
        get(&harness, "/v1/admin/nodes", &approver).await,
        get(&harness, &node_path, &approver).await,
        get(&harness, &format!("{node_path}/access"), &reader).await,
        get(&harness, "/v1/admin/sessions", &reader).await,
        get(
            &harness,
            &format!("/v1/admin/sessions/{session_id}"),
            &reader,
        )
        .await,
        get(&harness, "/v1/admin/sessions/missing", &reader).await,
        get(&harness, "/v1/admin/nodes?state=pending", &approver).await,
        call(
            &harness,
            Method::POST,
            "/v1/admin/enrolments/lookup",
            Some(&approver),
            Csrf::Missing,
            Some(&json!({"code": waiting.code})),
        )
        .await,
    ];
    for confirm in ["wrong", NODE_NAME, NODE_NAME] {
        replies.push(
            delete(
                &harness,
                &node_path,
                &approver,
                &json!({"confirm_name": confirm}),
            )
            .await,
        );
    }

    let mut secrets: Vec<String> = Vec::new();
    for enrolled in [&approved, &rejected, &waiting] {
        let normalized = enrolled.code.replace('-', "");
        secrets.extend([
            enrolled.code.clone(),
            normalized.clone(),
            sha256_hex(&normalized),
            enrolled.handle.clone(),
            enrolled.handle_hash(),
        ]);
    }
    for who in [&approver, &reader] {
        let cookie_secret = who.cookie.split_once('=').unwrap().1.to_owned();
        secrets.extend([sha256_hex(&cookie_secret), cookie_secret, who.csrf.clone()]);
    }
    for (_, intent) in &lookups {
        secrets.extend([intent.clone(), sha256_hex(intent)]);
    }

    for (reply, own_intent) in &lookups {
        let text = reply.text();
        assert_eq!(text.matches(own_intent.as_str()).count(), 1);
        let rest = text.replacen(own_intent.as_str(), "", 1);
        for secret in &secrets {
            assert!(!rest.contains(secret.as_str()), "{rest}");
        }
    }
    for reply in &replies {
        let text = reply.text();
        for secret in &secrets {
            assert!(!text.contains(secret.as_str()), "{}: {text}", reply.status);
        }
    }
}
