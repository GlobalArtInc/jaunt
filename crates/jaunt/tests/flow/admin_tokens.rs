use std::ffi::OsString;
use std::time::{Duration, SystemTime};

use jaunt::admin::{AdminContext, AdminError, NewToken, create_token, list_tokens, revoke_token};
use jaunt::admin_signature::content_digest;
use jaunt::agent::SshAgent;
use jaunt::profile::ProfileName;
use jaunt::store::ProfileStore;
use serde_json::json;

use crate::agent::login_with;
use crate::cli::{base_command, stderr, stdout};
use crate::support::{
    ADMIN_TOKEN, ADMIN_TOKEN_ID, Behavior, FakeServer, SeenRequest, USER_ID, serial_section,
};

const SIGNED_HEADERS: [&str; 4] = [
    "jaunt-certificate",
    "content-digest",
    "signature-input",
    "signature",
];

fn context<'a>(store: &'a ProfileStore, socket: Option<&'a OsString>) -> AdminContext<'a> {
    AdminContext {
        store,
        agent_socket: socket,
        clock: &SystemTime::now,
        agent_timeout: Duration::from_secs(10),
    }
}

fn assert_signed(request: &SeenRequest) {
    for name in SIGNED_HEADERS {
        assert!(request.header(name).is_some(), "{name} missing");
    }
    assert_eq!(
        request.header("content-digest"),
        Some(content_digest(&request.body).as_str())
    );
    assert!(request.header("authorization").is_none());
}

#[test]
fn tokens_are_created_listed_and_revoked_with_signed_requests() {
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    login_with(&server, &home, &SshAgent::new(None));
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    let context = context(&store, None);

    let created = create_token(
        &context,
        &NewToken {
            name: "ci-audit".to_owned(),
            scope: vec!["audit.read".to_owned()],
            ttl_secs: Some(3_600),
            cidrs: vec!["203.0.113.0/24".to_owned()],
        },
    )
    .unwrap();
    let listed = list_tokens(&context).unwrap();
    revoke_token(&context, ADMIN_TOKEN_ID).unwrap();
    let unknown = revoke_token(&context, "BBBBBBBBBBB").unwrap_err();
    let malformed = revoke_token(&context, "../whoami").unwrap_err();

    assert_eq!(created.secret.expose(), ADMIN_TOKEN);
    assert_eq!(created.token.id, ADMIN_TOKEN_ID);
    assert!(!format!("{created:?}").contains(&ADMIN_TOKEN[16..]));
    assert_eq!(listed.tokens.len(), 1);
    assert!(listed.truncated);
    assert_eq!(listed.tokens[0].creator, USER_ID);
    assert!(matches!(unknown, AdminError::UnknownToken));
    assert!(matches!(malformed, AdminError::UnknownToken));
    let requests = server.seen(|seen| seen.token_requests.clone());
    let shapes: Vec<(&str, &str)> = requests
        .iter()
        .map(|request| (request.method.as_str(), request.path.as_str()))
        .collect();
    assert_eq!(
        shapes,
        [
            ("POST", "/v1/admin/tokens"),
            ("GET", "/v1/admin/tokens"),
            ("DELETE", "/v1/admin/tokens/AbC-_09xyzQ"),
            ("DELETE", "/v1/admin/tokens/BBBBBBBBBBB"),
        ]
    );
    for request in &requests {
        assert_signed(request);
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
        json!({
            "name": "ci-audit",
            "scope": ["audit.read"],
            "ttl_secs": 3_600,
            "cidrs": ["203.0.113.0/24"],
        })
    );
    assert_eq!(requests[0].header("content-type"), Some("application/json"));
}

#[test]
fn the_binary_prints_the_secret_once_and_reads_a_token_only_from_a_file_or_the_environment() {
    let _serial = serial_section();
    let server = FakeServer::start(Behavior::default());
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    login_with(&server, &home, &SshAgent::new(None));
    let token_file = root.path().join("token");
    std::fs::write(&token_file, format!("{ADMIN_TOKEN}\n")).unwrap();
    let token_path = token_file.to_str().unwrap();

    let created = base_command(&home)
        .args([
            "admin",
            "tokens",
            "create",
            "--name",
            "ci-audit",
            "--scope",
            "audit.read",
            "--ttl",
            "30d",
        ])
        .output()
        .unwrap();
    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(stdout(&created), format!("{ADMIN_TOKEN}\n"));
    assert!(stderr(&created).contains("shown only this once"));
    assert!(!stderr(&created).contains(&ADMIN_TOKEN[16..]));

    let listed = base_command(&home)
        .args(["admin", "tokens", "ls"])
        .output()
        .unwrap();
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("ci-audit"));
    assert!(stdout(&listed).contains("Only part of the list is shown"));
    let listed_json = base_command(&home)
        .args(["admin", "tokens", "ls", "--format", "json"])
        .output()
        .unwrap();
    assert!(listed_json.status.success(), "{}", stderr(&listed_json));
    let body: serde_json::Value = serde_json::from_str(&stdout(&listed_json)).unwrap();
    assert_eq!(body["truncated"], true);

    let from_file = base_command(&home)
        .args(["admin", "--token", token_path, "whoami"])
        .output()
        .unwrap();
    assert!(from_file.status.success(), "{}", stderr(&from_file));
    assert!(stdout(&from_file).contains("ci-audit (AbC-_09xyzQ)"));
    assert!(stdout(&from_file).contains("audit.read"));
    assert!(!stdout(&from_file).contains(&ADMIN_TOKEN[16..]));

    let from_env = base_command(&home)
        .env("JAUNT_ADMIN_TOKEN", ADMIN_TOKEN)
        .args([
            "admin",
            "--token",
            "env",
            "--server",
            &server.url(),
            "whoami",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert!(from_env.status.success(), "{}", stderr(&from_env));
    let identity: serde_json::Value = serde_json::from_str(&stdout(&from_env)).unwrap();
    assert_eq!(identity["rights"], json!(["audit.read"]));

    let token_named = root.path().join(ADMIN_TOKEN);
    std::fs::write(&token_named, ADMIN_TOKEN).unwrap();
    let relative = base_command(&home)
        .current_dir(root.path())
        .args(["admin", "--token", &format!("./{ADMIN_TOKEN}"), "whoami"])
        .output()
        .unwrap();
    assert!(relative.status.success(), "{}", stderr(&relative));

    let hyphen = base_command(&home)
        .args(["admin", "tokens", "revoke", "-bcdefghijk"])
        .output()
        .unwrap();
    assert_eq!(hyphen.status.code(), Some(1), "{}", stderr(&hyphen));
    assert!(stderr(&hyphen).contains("no token has this id"));
    assert_eq!(
        server.seen(|seen| seen.token_requests.last().unwrap().path.clone()),
        "/v1/admin/tokens/-bcdefghijk"
    );

    let before = server.seen(|seen| seen.token_requests.len());
    for args in [
        vec!["admin", "--token", ADMIN_TOKEN, "whoami"],
        vec!["admin", "--token", "env", "tokens", "ls"],
        vec![
            "admin",
            "tokens",
            "create",
            "--name",
            "x",
            "--scope",
            "tokens.write",
        ],
    ] {
        let refused = base_command(&home)
            .env("JAUNT_ADMIN_TOKEN", ADMIN_TOKEN)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            refused.status.code(),
            Some(2),
            "{args:?}: {}",
            stderr(&refused)
        );
        assert!(!stderr(&refused).contains(&ADMIN_TOKEN[16..]), "{args:?}");
    }
    let requests = server.seen(|seen| seen.token_requests.clone());
    assert_eq!(requests.len(), before);
    let bearers: Vec<&SeenRequest> = requests
        .iter()
        .filter(|request| request.path == "/v1/admin/whoami")
        .collect();
    assert_eq!(bearers.len(), 3);
    for request in bearers {
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {ADMIN_TOKEN}").as_str())
        );
        assert!(request.header("signature").is_none());
    }
}
