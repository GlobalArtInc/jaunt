use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use jaunt_audit::{Classified, EventType};
use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

const AUDIT_TARGET: &str = "jaunt::audit";
const TRACING_MACROS: &[&str] = &["info", "warn", "error", "debug", "trace", "event"];

#[derive(Default)]
struct Scan {
    events: BTreeSet<String>,
    problems: Vec<String>,
    audit_literals: usize,
    audit_macros: usize,
}

fn string_value(literal: &proc_macro2::Literal) -> Option<String> {
    syn::parse_str::<syn::LitStr>(&literal.to_string())
        .ok()
        .map(|parsed| parsed.value())
}

fn split_arguments(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let mut segments: Vec<Vec<TokenTree>> = vec![Vec::new()];
    for token in tokens {
        match &token {
            TokenTree::Punct(punct) if punct.as_char() == ',' => segments.push(Vec::new()),
            _ => {
                if let Some(last) = segments.last_mut() {
                    last.push(token);
                }
            }
        }
    }
    segments
}

enum Value {
    Missing,
    Literal(String),
    Computed,
}

fn literal_after(segment: &[TokenTree], skip: usize) -> Value {
    match &segment[skip..] {
        [TokenTree::Literal(literal)] => match string_value(literal) {
            Some(text) => Value::Literal(text),
            None => Value::Computed,
        },
        _ => Value::Computed,
    }
}

fn target_of(segments: &[Vec<TokenTree>]) -> Value {
    for segment in segments {
        if let [TokenTree::Ident(name), TokenTree::Punct(colon), ..] = segment.as_slice()
            && name == "target"
            && colon.as_char() == ':'
        {
            return literal_after(segment, 2);
        }
    }
    Value::Missing
}

fn event_of(segments: &[Vec<TokenTree>]) -> Value {
    for segment in segments {
        let mut start = 0;
        while matches!(segment.get(start), Some(TokenTree::Punct(p)) if matches!(p.as_char(), '%' | '?'))
        {
            start += 1;
        }
        let named_event = match segment.get(start) {
            Some(TokenTree::Ident(name)) => name == "event",
            Some(TokenTree::Literal(literal)) => string_value(literal).as_deref() == Some("event"),
            _ => false,
        };
        if !named_event {
            continue;
        }
        return match segment.get(start + 1) {
            None => Value::Computed,
            Some(TokenTree::Punct(punct)) if punct.as_char() == '=' && start == 0 => {
                literal_after(segment, start + 2)
            }
            _ => continue,
        };
    }
    Value::Missing
}

impl Scan {
    fn inspect(&mut self, tokens: TokenStream, place: &str) {
        let segments = split_arguments(tokens);
        match target_of(&segments) {
            Value::Missing => {}
            Value::Computed => self.problems.push(format!(
                "unsupported form: the target of a tracing macro is not a string literal ({place})"
            )),
            Value::Literal(target) if target != AUDIT_TARGET => {}
            Value::Literal(_) => {
                self.audit_macros += 1;
                match event_of(&segments) {
                    Value::Literal(name) => {
                        if EventType::classify(&name) == Classified::Unknown {
                            self.problems
                                .push(format!("event {name:?} has no mapping ({place})"));
                        }
                        self.events.insert(name);
                    }
                    Value::Computed => self.problems.push(format!(
                        "unsupported form: the event field of an audit macro is not a string \
                         literal ({place})"
                    )),
                    Value::Missing => self.problems.push(format!(
                        "unsupported form: an audit macro has no event field ({place})"
                    )),
                }
            }
        }
    }

    fn walk(&mut self, tokens: TokenStream, place: &str) {
        let list: Vec<TokenTree> = tokens.into_iter().collect();
        for (index, token) in list.iter().enumerate() {
            match token {
                TokenTree::Group(group) => {
                    if let (Some(TokenTree::Ident(name)), Some(TokenTree::Punct(bang))) = (
                        index.checked_sub(2).and_then(|at| list.get(at)),
                        index.checked_sub(1).and_then(|at| list.get(at)),
                    ) && bang.as_char() == '!'
                        && TRACING_MACROS.iter().any(|known| name == known)
                    {
                        self.inspect(group.stream(), place);
                    }
                    self.walk(group.stream(), place);
                }
                TokenTree::Literal(literal) => {
                    if string_value(literal).as_deref() == Some(AUDIT_TARGET) {
                        self.audit_literals += 1;
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let tracing = mac
            .path
            .segments
            .last()
            .is_some_and(|last| TRACING_MACROS.iter().any(|known| last.ident == known));
        if tracing {
            self.inspect(mac.tokens.clone(), "a macro in the syntax tree");
        }
        self.walk(mac.tokens.clone(), "a nested macro");
        syn::visit::visit_macro(self, mac);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        if literal.value() == AUDIT_TARGET {
            self.audit_literals += 1;
        }
    }
}

fn scan_source(source: &str) -> Scan {
    let mut scan = Scan::default();
    match syn::parse_file(source) {
        Ok(file) => scan.visit_file(&file),
        Err(error) => scan
            .problems
            .push(format!("the source does not parse: {error}")),
    }
    if scan.audit_literals != scan.audit_macros {
        scan.problems.push(format!(
            "unsupported form: {} uses of the audit target literal but {} recognised macros",
            scan.audit_literals, scan.audit_macros
        ));
    }
    scan
}

fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn workspace_sources() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in fs::read_dir(&crates).unwrap() {
        let path = entry.unwrap().path();
        if path.file_name().is_some_and(|name| name == "jaunt-audit") {
            continue;
        }
        let source = path.join("src");
        if source.is_dir() {
            rust_files(&source, &mut files);
        }
    }
    files
}

#[test]
fn every_audit_event_emitted_by_the_workspace_is_mapped_or_explicitly_ignored() {
    let mut events = BTreeSet::new();
    let mut problems = Vec::new();
    for file in workspace_sources() {
        let scan = scan_source(&fs::read_to_string(&file).unwrap());
        events.extend(scan.events);
        problems.extend(
            scan.problems
                .into_iter()
                .map(|problem| format!("{}: {problem}", file.display())),
        );
    }

    assert!(problems.is_empty(), "{problems:#?}");
    for known in [
        "login.started",
        "cert.issued",
        "authz.deny",
        "session.start",
        "node.removed",
        "gate.ssh.auth",
        "agent.connected",
        "agent.ssh.end",
        "policy.reload",
        "agent.cert.rotated",
    ] {
        assert!(events.contains(known), "the scan did not find {known}");
    }
    assert!(events.len() > 40, "only {} events found", events.len());
}

fn problems_of(source: &str) -> Vec<String> {
    scan_source(source).problems
}

fn events_of(source: &str) -> Vec<String> {
    let scan = scan_source(source);
    assert!(scan.problems.is_empty(), "{:?}", scan.problems);
    scan.events.into_iter().collect()
}

#[test]
fn every_supported_spelling_is_found() {
    for source in [
        r#"fn f() { tracing::info!(target: "jaunt::audit", event = "login.started", x = 1); }"#,
        r#"fn f() { info!(target: "jaunt::audit", event="login.started"); }"#,
        "fn f() { tracing::warn!(\n    target: \"jaunt::audit\",\n    event =\n        \"login.started\",\n    x = 1\n); }",
        r#"fn f() { tracing::info!(target: "jaunt::audit", "event" = "login.started"); }"#,
        r#"fn f() { tracing::event!(target: "jaunt::audit", tracing::Level::INFO, event = "login.started"); }"#,
        r#"fn f() { tracing::error!(event = "login.started", target: "jaunt::audit"); }"#,
        r#"fn f() { tokio::select! { _ = a => { tracing::info!(target: "jaunt::audit", event = "login.started"); } } }"#,
        r#"fn f() { if matches!(x, Some(_)) { debug!(target: "jaunt::audit", event = "login.started"); } }"#,
    ] {
        assert_eq!(events_of(source), ["login.started"], "{source}");
    }
}

#[test]
fn every_bypass_spelling_fails_the_scan() {
    let cases = [
        (
            "const instead of a literal target",
            r#"const T: &str = "jaunt::audit"; fn f() { tracing::info!(target: T, event = "login.started"); }"#,
        ),
        (
            "the audit target literal bound to a constant",
            r#"const T: &str = "jaunt::audit"; fn f() { tracing::info!(target: "x", event = "y"); }"#,
        ),
        (
            "target taken from a variable",
            r#"fn f(t: &str) { tracing::info!(target: t, event = "login.started"); }"#,
        ),
        (
            "computed event name",
            r#"fn f(n: &str) { tracing::info!(target: "jaunt::audit", event = n); }"#,
        ),
        (
            "event name from a formatted value",
            r#"fn f() { tracing::info!(target: "jaunt::audit", event = %format!("a.{}", 1)); }"#,
        ),
        (
            "event name from a debug value",
            r#"fn f() { tracing::info!(target: "jaunt::audit", event = ?name); }"#,
        ),
        (
            "event name from a concat macro",
            r#"fn f() { tracing::info!(target: "jaunt::audit", event = concat!("a", ".b")); }"#,
        ),
        (
            "shorthand event field",
            r#"fn f(event: &str) { tracing::info!(target: "jaunt::audit", event); }"#,
        ),
        (
            "audit macro with no event field",
            r#"fn f() { tracing::info!(target: "jaunt::audit", "just a message"); }"#,
        ),
        (
            "an unmapped literal name",
            r#"fn f() { tracing::info!(target: "jaunt::audit", event = "revoke.nothing"); }"#,
        ),
        (
            "an unmapped literal name with no spaces",
            r#"fn f() { tracing::info!(target:"jaunt::audit",event="revoke.nothing"); }"#,
        ),
        (
            "a computed target inside a nested macro",
            r#"fn f() { tokio::select! { _ = a => { tracing::info!(target: T, event = "login.started"); } } }"#,
        ),
        (
            "the audit literal compared in code",
            r#"fn f(m: &M) -> bool { m.target() == "jaunt::audit" }"#,
        ),
    ];
    for (label, source) in cases {
        assert!(!problems_of(source).is_empty(), "{label} was not caught");
    }
}

#[test]
fn macros_that_are_not_audit_events_are_left_alone() {
    for source in [
        r#"fn f() { tracing::info!(target: "jaunt::daemon", event = name, "x"); }"#,
        r#"fn f() { tracing::info!(event = name, "no target"); }"#,
        r#"fn f() { tracing::info!("plain"); }"#,
        r#"fn f() { println!("jaunt"); }"#,
    ] {
        assert!(events_of(source).is_empty(), "{source}");
    }
}

#[test]
fn a_source_that_does_not_parse_is_a_problem() {
    assert!(!problems_of("fn f( {").is_empty());
}
