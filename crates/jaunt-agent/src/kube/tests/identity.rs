use http::{HeaderValue, Method, StatusCode};
use jaunt_kube::MAX_IMPERSONATION_GROUPS;

use super::support::{
    Alpn, CONFIGMAPS, Kube, SESSION, TOKEN, TestBody, alice, body_text, h1, h1_request, h2,
    h2_request, kube, message,
};

struct Row {
    access: jaunt_proto::ServiceAccess,
    headers: &'static [(&'static str, &'static str)],
    status: StatusCode,
    user: &'static str,
    groups: &'static [&'static str],
    says: &'static str,
}

fn row(
    access: jaunt_proto::ServiceAccess,
    headers: &'static [(&'static str, &'static str)],
    status: StatusCode,
    user: &'static str,
    groups: &'static [&'static str],
    says: &'static str,
) -> Row {
    Row {
        access,
        headers,
        status,
        user,
        groups,
        says,
    }
}

#[tokio::test]
async fn every_row_of_the_impersonation_table_is_applied_or_refused_before_the_api() {
    let kube_api = Kube::new().await;
    let two = || kube(&["alice@example.com", "bob@example.com"], &["view"]);
    let many: Vec<String> = (0..=MAX_IMPERSONATION_GROUPS)
        .map(|index| format!("group-{index}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let forbidden = StatusCode::FORBIDDEN;
    let rows = [
        row(
            alice(),
            &[],
            StatusCode::OK,
            "alice@example.com",
            &["view", "dev"],
            "",
        ),
        row(
            alice(),
            &[("impersonate-user", "alice@example.com")],
            StatusCode::OK,
            "alice@example.com",
            &["view", "dev"],
            "",
        ),
        row(
            two(),
            &[],
            forbidden,
            "",
            &[],
            "alice@example.com, bob@example.com",
        ),
        row(
            two(),
            &[("impersonate-user", "bob@example.com")],
            StatusCode::OK,
            "bob@example.com",
            &["view"],
            "",
        ),
        row(
            two(),
            &[("impersonate-user", "carol@example.com")],
            forbidden,
            "",
            &[],
            "allowed users: alice@example.com, bob@example.com",
        ),
        row(
            alice(),
            &[("impersonate-group", "dev")],
            StatusCode::OK,
            "alice@example.com",
            &["dev"],
            "",
        ),
        row(
            alice(),
            &[("impersonate-group", "dev"), ("impersonate-group", "admin")],
            forbidden,
            "",
            &[],
            "allowed groups: view, dev",
        ),
        row(
            alice(),
            &[("impersonate-uid", "1000")],
            forbidden,
            "",
            &[],
            "Impersonate-Uid",
        ),
        row(
            alice(),
            &[("impersonate-extra-scopes", "admin")],
            forbidden,
            "",
            &[],
            "Impersonate-Extra",
        ),
        row(
            alice(),
            &[("impersonate-extra-jaunt-session-id", "k-other")],
            forbidden,
            "",
            &[],
            "Impersonate-Extra",
        ),
        row(
            kube(&["system:admin"], &[]),
            &[],
            forbidden,
            "",
            &[],
            "cannot be applied",
        ),
        row(
            kube(&["alice@example.com"], &["view", "system:masters"]),
            &[],
            forbidden,
            "",
            &[],
            "cannot be applied",
        ),
        row(
            kube(
                &["alice@example.com\r\nimpersonate-group: system:masters"],
                &[],
            ),
            &[],
            forbidden,
            "",
            &[],
            "cannot be applied",
        ),
        row(
            kube(&["alice@example.com"], &["view\r\nx: y"]),
            &[],
            forbidden,
            "",
            &[],
            "cannot be applied",
        ),
        row(
            kube(&["alice@example.com"], &many),
            &[],
            forbidden,
            "",
            &[],
            "cannot be applied",
        ),
    ];
    let mut forwarded = 0;
    for (index, row) in rows.into_iter().enumerate() {
        let mut session = kube_api.open(row.access, Alpn::H2).await;
        let mut client = h2(session.take()).await;
        let mut request = h2_request(Method::GET, &format!("{CONFIGMAPS}/c"), TestBody::empty());
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_static("Bearer client-token"),
        );
        for (name, value) in row.headers {
            request
                .headers_mut()
                .append(*name, HeaderValue::from_static(value));
        }
        let (status, body) = body_text(client.send_request(request).await.unwrap()).await;
        assert_eq!(status, row.status, "row {index}: {body}");
        let seen = kube_api.api.seen();
        if status == StatusCode::OK {
            forwarded += 1;
            assert_eq!(seen.len(), forwarded, "row {index}");
            let last = seen.last().unwrap();
            assert_eq!(last.values("authorization"), [format!("Bearer {TOKEN}")]);
            assert_eq!(last.values("impersonate-user"), [row.user], "row {index}");
            assert_eq!(last.values("impersonate-group"), row.groups, "row {index}");
            assert_eq!(
                last.values("impersonate-extra-jaunt-session-id"),
                [SESSION],
                "row {index}"
            );
            assert!(last.values("impersonate-uid").is_empty(), "row {index}");
            assert!(
                last.headers
                    .keys()
                    .filter(|name| name.as_str().starts_with("impersonate-extra-"))
                    .all(|name| name == "impersonate-extra-jaunt-session-id"),
                "row {index}"
            );
        } else {
            assert_eq!(seen.len(), forwarded, "row {index} reached the API");
            assert!(message(&body).contains(row.says), "row {index}: {body}");
        }
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn http1_clients_get_the_same_identity_and_never_pass_their_credentials() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut client = h1(session.take()).await;
    let mut request = h1_request(Method::GET, &format!("{CONFIGMAPS}/c"), TestBody::empty());
    for (name, value) in [
        ("authorization", "Bearer client-token"),
        ("impersonate-user", "alice@example.com"),
        ("x-remote-user", "admin"),
        ("x-remote-group", "system:masters"),
    ] {
        request
            .headers_mut()
            .append(name, HeaderValue::from_static(value));
    }
    let (status, body) = body_text(client.send_request(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let seen = kube_api.api.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, Method::GET);
    assert_eq!(seen[0].path, format!("{CONFIGMAPS}/c"));
    assert_eq!(seen[0].values("authorization"), [format!("Bearer {TOKEN}")]);
    assert_eq!(seen[0].values("impersonate-user"), ["alice@example.com"]);
    assert!(seen[0].values("x-remote-user").is_empty());
    assert!(seen[0].values("x-remote-group").is_empty());
    assert!(seen[0].values("host").is_empty());
    session.cancel.cancel();
    session.finished().await;
}
