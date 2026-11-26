use http::header::{HeaderMap, HeaderName, HeaderValue};
use jaunt_kube::{
    IMPERSONATE_GROUP, IMPERSONATE_SESSION, IMPERSONATE_USER, ImpersonationError, KubeGroup,
    KubeUser, MAX_IMPERSONATION_GROUPS, MAX_SESSION_TAG_BYTES, MAX_SUBJECT_NAME_BYTES,
    RefusedHeader, SessionTag, SystemNames, impersonation_headers, is_subject_name,
    strip_client_headers,
};

fn headers(pairs: &[(&str, &[u8])]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_bytes(value).unwrap(),
        );
    }
    map
}

fn groups(names: &[&str]) -> Vec<KubeGroup> {
    names
        .iter()
        .map(|name| KubeGroup::new(*name).unwrap())
        .collect()
}

fn values(map: &HeaderMap, name: &str) -> Vec<String> {
    map.get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

#[test]
fn every_forbidden_header_is_stripped_in_any_case() {
    for (name, refused) in [
        ("Authorization", None),
        ("AUTHORIZATION", None),
        ("authorization", None),
        ("Impersonate-User", None),
        ("IMPERSONATE-USER", None),
        ("Impersonate-Group", None),
        ("impersonate-group", None),
        ("Impersonate-Uid", Some(RefusedHeader::Uid)),
        ("IMPERSONATE-UID", Some(RefusedHeader::Uid)),
        ("Impersonate-Extra-Scopes", Some(RefusedHeader::Extra)),
        (
            "impersonate-extra-jaunt-session-id",
            Some(RefusedHeader::Extra),
        ),
        ("Impersonate-Extra-%41", Some(RefusedHeader::Extra)),
        ("Impersonate-Future", Some(RefusedHeader::Other)),
    ] {
        let mut map = headers(&[(name, b"value"), ("accept", b"application/json")]);
        let stripped = strip_client_headers(&mut map);
        assert_eq!(map.len(), 1, "{name} was not stripped");
        assert!(
            map.contains_key("accept"),
            "{name} took an allowed header with it"
        );
        assert!(!stripped.is_empty(), "{name} was not reported");
        assert_eq!(stripped.refused(), refused.as_slice(), "{name}");
        assert_eq!(stripped.must_refuse(), refused.is_some(), "{name}");
    }
}

#[test]
fn the_report_carries_requested_names_but_never_the_credential() {
    let mut map = headers(&[
        ("authorization", b"Bearer sekret-token"),
        ("Impersonate-User", b"alice@example.com"),
        ("Impersonate-Group", b"dev"),
        ("impersonate-group", b"ops"),
        ("Impersonate-Uid", b"1"),
        ("Impersonate-Extra-A", b"x"),
        ("Impersonate-Extra-B", b"y"),
        ("x-request-id", b"abc"),
    ]);
    let stripped = strip_client_headers(&mut map);
    assert!(stripped.had_authorization());
    assert_eq!(stripped.requested_users(), ["alice@example.com"]);
    assert_eq!(stripped.requested_groups(), ["dev", "ops"]);
    assert_eq!(
        stripped.refused(),
        [RefusedHeader::Uid, RefusedHeader::Extra]
    );
    assert!(!format!("{stripped:?}").contains("sekret"));
    assert_eq!(map.len(), 1);
}

#[test]
fn unreadable_requested_names_force_a_refusal() {
    let mut map = headers(&[("Impersonate-User", b"al\xffice")]);
    let stripped = strip_client_headers(&mut map);
    assert!(stripped.had_unreadable_value());
    assert!(stripped.must_refuse());
    assert!(stripped.requested_users().is_empty());
    assert!(map.is_empty());
}

#[test]
fn front_proxy_identity_headers_are_stripped_without_refusal() {
    let mut map = headers(&[
        ("X-Remote-User", b"admin"),
        ("x-remote-group", b"system:masters"),
        ("X-Remote-Extra-Scopes", b"all"),
        ("accept", b"*/*"),
    ]);
    let stripped = strip_client_headers(&mut map);
    assert!(stripped.had_remote_identity());
    assert!(!stripped.must_refuse());
    assert!(!stripped.is_empty());
    assert!(stripped.requested_users().is_empty());
    assert_eq!(map.len(), 1);
}

#[test]
fn clean_requests_report_nothing() {
    let mut map = headers(&[
        ("accept", b"*/*"),
        ("x-impersonate-user", b"bob"),
        ("x-remotes", b"1"),
    ]);
    let stripped = strip_client_headers(&mut map);
    assert!(stripped.is_empty());
    assert_eq!(map.len(), 3);
}

#[test]
fn the_group_count_is_bounded() {
    let session = SessionTag::new("s-1").unwrap();
    let user = KubeUser::new("alice").unwrap();
    let names: Vec<String> = (0..=MAX_IMPERSONATION_GROUPS)
        .map(|index| format!("g{index}"))
        .collect();
    let mut list: Vec<KubeGroup> = names
        .iter()
        .map(|name| KubeGroup::new(name.as_str()).unwrap())
        .collect();
    assert_eq!(
        impersonation_headers(&user, &list, &session, SystemNames::Refuse),
        Err(ImpersonationError::TooManyGroups)
    );
    list.pop();
    list.extend(list.clone());
    let built = impersonation_headers(&user, &list, &session, SystemNames::Refuse).unwrap();
    assert_eq!(
        values(&built, IMPERSONATE_GROUP).len(),
        MAX_IMPERSONATION_GROUPS
    );
}

#[test]
fn subject_names_follow_the_policy_rule() {
    let longest = "a".repeat(MAX_SUBJECT_NAME_BYTES);
    let too_long = "a".repeat(MAX_SUBJECT_NAME_BYTES + 1);
    for (name, valid) in [
        ("alice@example.com", true),
        ("system:masters", true),
        ("oidc:dev+ops=1_x.y", true),
        ("Dev-Team", true),
        (longest.as_str(), true),
        ("", false),
        (too_long.as_str(), false),
        ("-dev", false),
        ("dev team", false),
        ("dev,ops", false),
        ("dev\r\nX-Evil: 1", false),
        ("d\u{e9}v", false),
        ("dev/ops", false),
    ] {
        assert_eq!(is_subject_name(name), valid, "{name:?}");
        assert_eq!(KubeUser::new(name).is_ok(), valid, "{name:?}");
        assert_eq!(KubeGroup::new(name).is_ok(), valid, "{name:?}");
    }
    assert_eq!(KubeUser::new("-x"), Err(ImpersonationError::InvalidUser));
    assert_eq!(KubeGroup::new("-x"), Err(ImpersonationError::InvalidGroup));
}

#[test]
fn session_tags_are_short_header_safe_ids() {
    let longest = "a".repeat(MAX_SESSION_TAG_BYTES);
    let too_long = "a".repeat(MAX_SESSION_TAG_BYTES + 1);
    for (tag, valid) in [
        ("0b7c5e2a-1f00-4c1e-9d3a-6c2f1e0d9b8a", true),
        (longest.as_str(), true),
        ("", false),
        (too_long.as_str(), false),
        ("a b", false),
        ("a\n", false),
        ("a:b", false),
    ] {
        assert_eq!(SessionTag::new(tag).is_ok(), valid, "{tag:?}");
    }
}

#[test]
fn builds_user_groups_and_session_headers() {
    let user = KubeUser::new("alice@example.com").unwrap();
    let session = SessionTag::new("s-1").unwrap();
    let built = impersonation_headers(
        &user,
        &groups(&["dev", "ops", "dev"]),
        &session,
        SystemNames::Refuse,
    )
    .unwrap();
    assert_eq!(values(&built, IMPERSONATE_USER), ["alice@example.com"]);
    assert_eq!(values(&built, IMPERSONATE_GROUP), ["dev", "ops"]);
    assert_eq!(values(&built, IMPERSONATE_SESSION), ["s-1"]);
    assert_eq!(built.len(), 4);

    let without_groups = impersonation_headers(&user, &[], &session, SystemNames::Refuse).unwrap();
    assert!(without_groups.get(IMPERSONATE_GROUP).is_none());
    assert_eq!(without_groups.len(), 2);
}

#[test]
fn system_names_need_the_caller_flag() {
    let session = SessionTag::new("s-1").unwrap();
    let alice = KubeUser::new("alice").unwrap();
    for (user, group_names, refused) in [
        (
            "alice",
            &["system:masters"][..],
            ImpersonationError::SystemGroup,
        ),
        (
            "alice",
            &["dev", "SYSTEM:masters"][..],
            ImpersonationError::SystemGroup,
        ),
        (
            "alice",
            &["System:Authenticated"][..],
            ImpersonationError::SystemGroup,
        ),
        ("system:admin", &[][..], ImpersonationError::SystemUser),
        (
            "SyStEm:kube-controller-manager",
            &[][..],
            ImpersonationError::SystemUser,
        ),
    ] {
        let user = KubeUser::new(user).unwrap();
        let group_list = groups(group_names);
        assert_eq!(
            impersonation_headers(&user, &group_list, &session, SystemNames::Refuse),
            Err(refused),
            "{user:?} {group_names:?}"
        );
        let allowed =
            impersonation_headers(&user, &group_list, &session, SystemNames::Allow).unwrap();
        assert_eq!(values(&allowed, IMPERSONATE_USER), [user.as_str()]);
        assert_eq!(values(&allowed, IMPERSONATE_GROUP), group_names);
    }
    for near_miss in ["systemx:masters", "system-masters", "my-system:masters"] {
        assert!(
            impersonation_headers(&alice, &groups(&[near_miss]), &session, SystemNames::Refuse)
                .is_ok(),
            "{near_miss}"
        );
    }
}
