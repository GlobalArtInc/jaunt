mod common;

use std::fs;

use common::{load_err, load_ok, write_dir};
use jaunt_policy::{Expect, load_dir, run_access_tests};

const HEAD: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: r }\n";
const EMPTY_SET_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const TWO_FILE_HASH: &str = "52b3f71afc2f9d623335ce59bb95f95cd84e1a88b485f02708566872da018392";

fn valid_role(name: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [deploy] }}\n"
    )
}

fn assert_rejected(
    label: &str,
    files: &[(&str, &str)],
    file: &str,
    document: Option<usize>,
    fragment: &str,
) {
    let errors = load_err(files);
    let found = errors.errors().iter().any(|error| {
        error.file == file && error.document == document && error.message.contains(fragment)
    });
    assert!(
        found,
        "{label}: expected {file} {document:?} {fragment:?} in\n{errors}"
    );
}

#[test]
fn malformed_documents_are_rejected_with_file_and_document() {
    let unknown_field = format!("{HEAD}spec:\n  memberz: {{}}\n");
    let nested_unknown = format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: [a] }}, loginz: [x] }}\n");
    let top_unknown = format!("{HEAD}spec: {{}}\nextra: 1\n");
    let wrong_version = "apiVersion: jaunt/v2\nkind: Role\nmetadata: { name: r }\nspec: {}\n";
    let wrong_kind = "apiVersion: jaunt/v1\nkind: role\nmetadata: { name: r }\nspec: {}\n";
    let missing_kind = "apiVersion: jaunt/v1\nmetadata: { name: r }\nspec: {}\n";
    let empty_selector = format!("{HEAD}spec:\n  ssh: {{ nodes: {{}}, logins: [x] }}\n");
    let empty_values = format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: [] }}, logins: [x] }}\n");
    let embedded =
        format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: [a] }}, logins: ['x-{{username}}'] }}\n");
    let bad_login = format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: [a] }}, logins: ['a b'] }}\n");
    let bad_permission = format!("{HEAD}spec:\n  admin: [nodes.delete]\n");
    let numeric_label = format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: [1] }}, logins: [x] }}\n");
    let scalar_values = format!("{HEAD}spec:\n  ssh: {{ nodes: {{ env: prod }}, logins: [x] }}\n");
    let loose_bool = format!(
        "{HEAD}spec:\n  ssh: {{ nodes: {{ env: [a] }}, logins: [x], portForwarding: yes }}\n"
    );
    let duplicate_key = format!("{HEAD}spec: {{}}\nspec: {{}}\n");
    let test_extra = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: a@b.c, node: {}, login: x, expect: deny, note: n }\n";
    let test_expect = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: a@b.c, node: {}, login: x, expect: maybe }\n";

    let cases: Vec<(&str, &str, &str)> = vec![
        ("unknown field", &unknown_field, "unknown field `memberz`"),
        (
            "nested unknown field",
            &nested_unknown,
            "unknown field `loginz`",
        ),
        (
            "top-level unknown field",
            &top_unknown,
            "unknown field `extra`",
        ),
        ("apiVersion", wrong_version, "unsupported apiVersion"),
        ("kind case", wrong_kind, "unknown variant `role`"),
        ("missing kind", missing_kind, "missing field `kind`"),
        (
            "empty selector",
            &empty_selector,
            "selector must not be empty",
        ),
        (
            "empty value list",
            &empty_values,
            "must list at least one value",
        ),
        ("embedded placeholder", &embedded, "standalone {username}"),
        ("invalid literal login", &bad_login, "not a valid login"),
        (
            "unknown permission",
            &bad_permission,
            "unknown admin permission `nodes.delete`",
        ),
        ("non-string label", &numeric_label, "expected a string"),
        (
            "scalar instead of list",
            &scalar_values,
            "expected a sequence",
        ),
        ("loose boolean", &loose_bool, "expected a boolean"),
        ("duplicate key", &duplicate_key, "duplicate mapping key"),
        ("missing spec", HEAD, "missing field `spec`"),
        ("test unknown field", test_extra, "unknown field `note`"),
        ("test expect", test_expect, "unknown variant `maybe`"),
    ];
    for (label, content, fragment) in cases {
        assert_rejected(label, &[("a.yaml", content)], "a.yaml", Some(1), fragment);
    }
}

#[test]
fn document_numbers_count_every_document_in_the_file() {
    let good = valid_role("good");
    let second_bad = format!("{good}---\napiVersion: jaunt/v1\nkind: Nope\nspec: {{}}\n");
    let files = [("a.yaml", second_bad.as_str())];
    assert_rejected(
        "second",
        &files,
        "a.yaml",
        Some(2),
        "unknown variant `Nope`",
    );

    let after_empty = format!("{good}---\n---\napiVersion: jaunt/v1\nkind: Nope\nspec: {{}}\n");
    let files = [("a.yaml", after_empty.as_str())];
    assert_rejected("empty", &files, "a.yaml", Some(2), "document is empty");
    assert_rejected(
        "after empty",
        &files,
        "a.yaml",
        Some(3),
        "unknown variant `Nope`",
    );

    let explicit_null = format!("--- !!null\n---\n{good}");
    let files = [("a.yaml", explicit_null.as_str())];
    assert_rejected(
        "tagged null",
        &files,
        "a.yaml",
        Some(1),
        "document is empty",
    );

    let broken = format!("{good}---\nkey: [unclosed\n");
    let files = [("a.yaml", broken.as_str())];
    assert_rejected("syntax", &files, "a.yaml", Some(2), "YAML syntax error");

    assert_rejected(
        "no documents",
        &[("a.yaml", "\n")],
        "a.yaml",
        None,
        "no documents",
    );
}

#[test]
fn role_names_must_be_unique_across_the_set() {
    let role = valid_role("dup");
    let same_file = format!("{role}---\n{role}");
    let files = [("a.yaml", same_file.as_str())];
    assert_rejected(
        "same file",
        &files,
        "a.yaml",
        Some(2),
        "duplicate role name \"dup\"",
    );
    let files = [("a.yaml", role.as_str()), ("b.yml", role.as_str())];
    assert_rejected(
        "two files",
        &files,
        "b.yml",
        Some(1),
        "first defined in a.yaml document 1",
    );
}

#[test]
fn every_error_is_collected_not_just_the_first() {
    let wrong_version = "apiVersion: jaunt/v2\nkind: Role\nmetadata: { name: r }\nspec: {}\n";
    let unknown_field = format!("{HEAD}spec:\n  memberz: {{}}\n");
    let errors = load_err(&[
        ("a.yaml", wrong_version),
        ("b.yaml", &unknown_field),
        ("c.yaml", "\n"),
    ]);
    let files: Vec<&str> = errors.errors().iter().map(|e| e.file.as_str()).collect();
    assert_eq!(files, ["a.yaml", "b.yaml", "c.yaml"]);
    assert_eq!(errors.messages().len(), 3);
}

#[test]
fn only_plain_policy_files_are_read() {
    let role = valid_role("visible");
    let invalid = "this is not yaml: [";
    let dir = write_dir(&[
        ("a.yaml", role.as_str()),
        ("b.yml", &valid_role("second")),
        ("notes.txt", invalid),
        (".hidden.yaml", invalid),
        ("c.yaml.bak", invalid),
        ("d.YAML", invalid),
    ]);
    fs::create_dir(dir.path().join("nested.yaml")).expect("create nested dir");
    fs::write(dir.path().join("nested.yaml").join("e.yaml"), invalid).expect("write nested file");
    let set = load_dir(dir.path()).expect("only a.yaml and b.yml are read");
    assert_eq!(set.hash().len(), 64);

    let missing = dir.path().join("missing");
    let errors = load_dir(&missing).expect_err("missing directory must be rejected");
    assert_eq!(errors.errors().len(), 1);
}

#[test]
fn files_that_are_not_utf8_are_rejected() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("a.yaml"), [0xff, 0xfe, 0x00]).expect("write file");
    let errors = load_dir(dir.path()).expect_err("invalid UTF-8 must be rejected");
    assert!(errors.to_string().contains("not valid UTF-8"), "{errors}");
}

#[test]
fn access_tests_run_and_catch_disagreement() {
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: alice@example.com, node: { env: prod, name: web-1 }, login: deploy, expect: allow }\n  - { user: alice@example.com, node: { env: prod }, login: root, expect: deny }\n  - { user: alice@example.com, node: { env: prod }, login: root, expect: allow }\n  - { user: bob@example.com, groups: [ops], username: bobby, node: { env: dev }, login: bobby, expect: allow }\n  - { user: bob@example.com, node: { env: prod }, login: bob, expect: allow }\n";
    let roles = format!(
        "{}---\napiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: ops }}\nspec:\n  members: {{ groups: [ops] }}\n  ssh: {{ nodes: {{ env: [dev] }}, logins: ['{{username}}'] }}\n",
        valid_role("prod")
    );
    let set = load_ok(&[("a.yaml", &roles), ("b.yaml", tests)]);
    assert_eq!(set.tests().len(), 5);
    assert_eq!(set.tests()[0].node.name, "web-1");
    assert!(!set.tests()[0].node.labels.contains_key("name"));
    assert_eq!(set.tests()[1].username, "alice");
    assert_eq!(set.tests()[3].expect, Expect::Allow);

    let results = run_access_tests(&set);
    let passed: Vec<bool> = results.iter().map(|result| result.passed).collect();
    assert_eq!(passed, [true, true, false, true, false]);
    assert_eq!(results[2].index, 2);
    assert!(
        results[2].description.contains("expected allow got deny"),
        "{}",
        results[2].description
    );
}

#[test]
fn hash_covers_names_and_contents_in_alphabetical_order() {
    let first = "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n";
    let second = "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n---\napiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n";
    let set = load_ok(&[("b.yml", second), ("a.yaml", first)]);
    assert_eq!(set.hash(), TWO_FILE_HASH);

    let reversed = load_ok(&[("a.yaml", first), ("b.yml", second)]);
    assert_eq!(set.hash(), reversed.hash());

    let edited = load_ok(&[("a.yaml", first), ("b.yml", first)]);
    assert_ne!(set.hash(), edited.hash());
    let renamed = load_ok(&[("a.yaml", first), ("c.yml", second)]);
    assert_ne!(set.hash(), renamed.hash());
    assert_eq!(load_ok(&[]).hash(), EMPTY_SET_HASH);
}

#[cfg(unix)]
#[test]
fn directory_is_resolved_once_and_a_vanished_generation_fails_the_whole_load() {
    use std::os::unix::fs::symlink;

    let role = valid_role("ops");
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n";
    let real = tempfile::tempdir().expect("create temp dir");
    let generation = real.path().join("..gen1");
    fs::create_dir(&generation).expect("create generation dir");
    fs::write(generation.join("a.yaml"), &role).expect("write a.yaml");
    fs::write(generation.join("b.yaml"), tests).expect("write b.yaml");
    symlink("..gen1", real.path().join("..data")).expect("link data dir");
    symlink("..data/a.yaml", real.path().join("a.yaml")).expect("link a.yaml");
    symlink("..data/b.yaml", real.path().join("b.yaml")).expect("link b.yaml");

    let outer = tempfile::tempdir().expect("create temp dir");
    let through_link = outer.path().join("policy");
    symlink(real.path(), &through_link).expect("link policy dir");
    let set = load_dir(&through_link).expect("a symlinked directory must load");
    assert_eq!(
        set.hash(),
        load_ok(&[("a.yaml", &role), ("b.yaml", tests)]).hash()
    );

    fs::remove_dir_all(&generation).expect("remove generation");
    let errors = load_dir(&through_link).expect_err("a vanished generation must fail the load");
    assert!(errors.to_string().contains("..data"), "{errors}");
}

#[cfg(unix)]
#[test]
fn files_come_from_the_resolved_generation_only() {
    use std::os::unix::fs::symlink;

    let role = valid_role("ops");
    let dir = tempfile::tempdir().expect("create temp dir");
    let generation = dir.path().join("..gen1");
    fs::create_dir(&generation).expect("create generation dir");
    fs::write(generation.join("a.yaml"), &role).expect("write a.yaml");
    symlink("..gen1", dir.path().join("..data")).expect("link data dir");
    symlink("..data/a.yaml", dir.path().join("a.yaml")).expect("link a.yaml");
    symlink("..data/new.yaml", dir.path().join("new.yaml")).expect("link not yet published key");

    let set = load_dir(dir.path()).expect("keys of a generation not yet published are ignored");
    assert_eq!(set.hash(), load_ok(&[("a.yaml", &role)]).hash());
}

#[cfg(unix)]
#[test]
fn files_resolving_outside_the_policy_directory_are_rejected_unread() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().expect("create temp dir");
    let secret = outside.path().join("secret.yaml");
    fs::write(
        &secret,
        "apiVersion: jaunt/v1
kind: SECRET-MARKER [
",
    )
    .expect("write outside file");

    let plain = tempfile::tempdir().expect("create temp dir");
    symlink(&secret, plain.path().join("leak.yaml")).expect("link outside file");
    let generation_root = tempfile::tempdir().expect("create temp dir");
    let generation = generation_root.path().join("..gen1");
    fs::create_dir(&generation).expect("create generation dir");
    symlink(&secret, generation.join("leak.yaml")).expect("link outside file");
    symlink("..gen1", generation_root.path().join("..data")).expect("link data dir");

    for dir in [plain.path(), generation_root.path()] {
        let errors = load_dir(dir).expect_err("outside files must be rejected");
        assert_eq!(errors.errors().len(), 1, "{errors}");
        assert_eq!(errors.errors()[0].file, "leak.yaml");
        assert!(
            errors.to_string().contains("outside the policy directory"),
            "{errors}"
        );
        assert!(!errors.to_string().contains("SECRET-MARKER"), "{errors}");
    }
}

#[cfg(unix)]
#[test]
fn generation_link_must_stay_inside_the_policy_directory() {
    use std::os::unix::fs::symlink;

    let outside = tempfile::tempdir().expect("create temp dir");
    fs::write(outside.path().join("a.yaml"), valid_role("ops")).expect("write outside file");
    let dir = tempfile::tempdir().expect("create temp dir");
    symlink(outside.path(), dir.path().join("..data")).expect("link data dir");
    let errors = load_dir(dir.path()).expect_err("an escaping ..data must be rejected");
    assert!(
        errors.to_string().contains("inside the policy directory"),
        "{errors}"
    );
}
