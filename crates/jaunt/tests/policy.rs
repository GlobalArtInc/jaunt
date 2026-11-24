use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy] }\n";
const PASSING: &str = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: alice@example.com, node: { env: prod }, login: deploy, expect: allow }\n";
const FAILING: &str = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: alice@example.com, node: { env: prod }, login: root, expect: allow }\n";

fn jaunt(args: &[&str], dir: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_jaunt"));
    command.args(args);
    if let Some(dir) = dir {
        command.arg(dir);
    }
    command.output().expect("run the jaunt binary")
}

fn check(files: &[(&str, &str)], extra: &[&str]) -> Output {
    let dir = tempfile::tempdir().expect("create temp dir");
    for (name, content) in files {
        fs::write(dir.path().join(name), content).expect("write policy file");
    }
    let mut args = vec!["policy", "check"];
    args.extend_from_slice(extra);
    jaunt(&args, Some(dir.path()))
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

#[test]
fn valid_directory_exits_zero_with_a_summary() {
    let output = check(&[("a.yaml", ROLE), ("b.yaml", PASSING)], &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
    let text = stdout(&output);
    assert!(text.contains("PASS b.yaml document 1 entry 1:"), "{text}");
    assert!(text.contains("1 tests, 1 passed, 0 failed"), "{text}");
}

#[test]
fn failing_access_test_exits_one_with_a_fail_line() {
    let output = check(&[("a.yaml", ROLE), ("b.yaml", FAILING)], &[]);
    assert_eq!(output.status.code(), Some(1));
    let text = stdout(&output);
    assert!(text.contains("FAIL b.yaml document 1 entry 1:"), "{text}");
    assert!(text.contains("expected allow got deny"), "{text}");
}

#[test]
fn invalid_yaml_exits_one() {
    let output = check(&[("a.yaml", "kind: [unclosed\n")], &[]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stdout(&output).contains("ERROR a.yaml"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn missing_directory_exits_two_with_a_diagnostic_on_stderr() {
    let parent = tempfile::tempdir().expect("create temp dir");
    let output = jaunt(&["policy", "check"], Some(&parent.path().join("missing")));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn json_format_has_the_documented_keys() {
    let passing = check(
        &[("a.yaml", ROLE), ("b.yaml", PASSING)],
        &["--format", "json"],
    );
    assert_eq!(passing.status.code(), Some(0));
    let report: Value = serde_json::from_str(&stdout(&passing)).expect("stdout is JSON");
    assert_eq!(report["loaded"], true);
    assert_eq!(report["errors"], Value::Array(Vec::new()));
    assert_eq!(report["tests"][0]["passed"], true);
    assert_eq!(report["tests"][0]["index"], 0);

    let failing = check(
        &[("a.yaml", ROLE), ("b.yaml", FAILING)],
        &["--format", "json"],
    );
    assert_eq!(failing.status.code(), Some(1));
    let report: Value = serde_json::from_str(&stdout(&failing)).expect("stdout is JSON");
    assert_eq!(report["tests"][0]["passed"], false);

    let invalid = check(&[("a.yaml", "kind: Nope\n")], &["--format", "json"]);
    assert_eq!(invalid.status.code(), Some(1));
    let report: Value = serde_json::from_str(&stdout(&invalid)).expect("stdout is JSON");
    assert_eq!(report["loaded"], false);
    assert_eq!(report["tests"], Value::Array(Vec::new()));
    assert_eq!(report["errors"].as_array().map(Vec::len), Some(1));
}

#[test]
fn schema_is_json_and_byte_identical_across_runs() {
    let first = jaunt(&["policy", "schema"], None);
    let second = jaunt(&["policy", "schema"], None);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(first.stdout, second.stdout);
    let schema: Value = serde_json::from_str(&stdout(&first)).expect("stdout is JSON");
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["oneOf"].as_array().map(Vec::len), Some(2));
}

#[test]
fn empty_directory_exits_one_in_both_formats() {
    let text = check(&[], &[]);
    assert_eq!(text.status.code(), Some(1));
    assert!(
        stdout(&text).contains("no policy documents found"),
        "{}",
        stdout(&text)
    );

    let json = check(&[], &["--format", "json"]);
    assert_eq!(json.status.code(), Some(1));
    let report: Value = serde_json::from_str(&stdout(&json)).expect("stdout is JSON");
    assert_eq!(report["loaded"], false);
    assert_eq!(report["errors"][0], "no policy documents found");
}
