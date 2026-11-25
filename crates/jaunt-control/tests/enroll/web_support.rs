use axum::body::Body;
use axum::http::{Method, Request, header};
use serde_json::{Value, json};

use crate::session_support::{apply_policy, user};
use crate::support::{Enrolled, Harness, Options, PUBLIC_ORIGIN, Reply, send};

pub const FOREIGN_ORIGIN: &str = "https://evil.example";

pub const ADMIN_ROLES: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: approvers }\nspec:\n  \
     members: { users: [approver@example.com] }\n  admin: [nodes.approve]\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: readers }\nspec:\n  \
     members: { users: [reader@example.com] }\n  admin: [sessions.read]\n";

pub struct Admin {
    pub user_id: String,
    pub cookie: String,
    pub csrf: String,
}

impl Admin {
    pub fn actor(&self) -> String {
        format!("web:{}", self.user_id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Csrf {
    Valid,
    Missing,
    ForeignOrigin,
}

pub async fn web_harness(extra_roles: &[String]) -> Harness {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    let mut roles = vec![ADMIN_ROLES.to_owned()];
    roles.extend(extra_roles.iter().cloned());
    apply_policy(&harness, &roles);
    harness
}

pub async fn admin(harness: &Harness, subject: &str) -> Admin {
    let user_id = user(harness, subject, &[]).await;
    let opened = harness
        .control
        .open_web_session(&user_id)
        .await
        .expect("a web session for the test admin");
    Admin {
        user_id,
        cookie: opened.cookie,
        csrf: opened.csrf_token,
    }
}

pub async fn call(
    harness: &Harness,
    method: Method,
    path: &str,
    admin: Option<&Admin>,
    csrf: Csrf,
    body: Option<&Value>,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(admin) = admin {
        builder = builder.header(header::COOKIE, &admin.cookie);
        match csrf {
            Csrf::Valid => {
                builder = builder
                    .header("x-jaunt-csrf", &admin.csrf)
                    .header(header::ORIGIN, PUBLIC_ORIGIN);
            }
            Csrf::Missing => builder = builder.header(header::ORIGIN, PUBLIC_ORIGIN),
            Csrf::ForeignOrigin => {
                builder = builder
                    .header("x-jaunt-csrf", &admin.csrf)
                    .header(header::ORIGIN, FOREIGN_ORIGIN);
            }
        }
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    send(harness.router.clone(), request).await
}

pub async fn get(harness: &Harness, path: &str, admin: &Admin) -> Reply {
    call(harness, Method::GET, path, Some(admin), Csrf::Valid, None).await
}

pub async fn post(harness: &Harness, path: &str, admin: &Admin, body: &Value) -> Reply {
    call(
        harness,
        Method::POST,
        path,
        Some(admin),
        Csrf::Valid,
        Some(body),
    )
    .await
}

pub async fn delete(harness: &Harness, path: &str, admin: &Admin, body: &Value) -> Reply {
    call(
        harness,
        Method::DELETE,
        path,
        Some(admin),
        Csrf::Valid,
        Some(body),
    )
    .await
}

pub async fn lookup(harness: &Harness, admin: &Admin, code: &str) -> Reply {
    post(
        harness,
        "/v1/admin/enrolments/lookup",
        admin,
        &json!({ "code": code }),
    )
    .await
}

pub struct Looked {
    pub enrolment_id: String,
    pub intent: String,
}

pub async fn looked_up(harness: &Harness, admin: &Admin, enrolled: &Enrolled) -> Looked {
    let reply = lookup(harness, admin, &enrolled.code).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let body = reply.json();
    Looked {
        enrolment_id: body["enrolment"]["id"].as_str().unwrap().to_owned(),
        intent: body["intent"].as_str().unwrap().to_owned(),
    }
}

pub async fn approve_with(
    harness: &Harness,
    admin: &Admin,
    looked: &Looked,
    labels: Option<Value>,
) -> Reply {
    let mut body = json!({ "intent": looked.intent });
    if let Some(labels) = labels {
        body["labels"] = labels;
    }
    post(
        harness,
        &format!("/v1/admin/enrolments/{}/approve", looked.enrolment_id),
        admin,
        &body,
    )
    .await
}

pub async fn reject_with(harness: &Harness, admin: &Admin, looked: &Looked) -> Reply {
    post(
        harness,
        &format!("/v1/admin/enrolments/{}/reject", looked.enrolment_id),
        admin,
        &json!({ "intent": looked.intent }),
    )
    .await
}
