mod common;

use common::{load_err, load_ok};

const VALID_DOCUMENT: &str = "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n";
const INVALID_DOCUMENT: &str = "apiVersion: jaunt/v1\nkind: Nope\nspec: {}\n";
const MIB: usize = 1024 * 1024;

fn padded(size: usize) -> String {
    format!(
        "{VALID_DOCUMENT}{}",
        "\n".repeat(size - VALID_DOCUMENT.len())
    )
}

fn numbered(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("f{index:03}.yaml"))
        .collect()
}

#[test]
fn a_file_over_one_mib_is_rejected() {
    let at_limit = padded(MIB);
    load_ok(&[("a.yaml", &at_limit)]);

    let over_limit = padded(MIB + 1);
    let errors = load_err(&[("a.yaml", &over_limit)]);
    assert_eq!(errors.errors().len(), 1, "{errors}");
    assert_eq!(errors.errors()[0].file, "a.yaml");
    assert_eq!(errors.errors()[0].document, None);
    assert!(errors.errors()[0].message.contains("1 MiB"), "{errors}");
}

#[test]
fn more_than_512_files_are_rejected() {
    let names = numbered(513);
    let files: Vec<(&str, &str)> = names
        .iter()
        .map(|name| (name.as_str(), VALID_DOCUMENT))
        .collect();
    load_ok(&files[..512]);
    let errors = load_err(&files);
    assert!(
        errors.to_string().contains("more than 512 policy files"),
        "{errors}"
    );
}

#[test]
fn a_set_over_eight_mib_is_rejected() {
    let names: Vec<String> = ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
        .iter()
        .map(|stem| format!("{stem}.yaml"))
        .collect();
    let content = padded(MIB);
    let files: Vec<(&str, &str)> = names
        .iter()
        .map(|name| (name.as_str(), content.as_str()))
        .collect();
    load_ok(&files[..8]);
    let errors = load_err(&files);
    assert_eq!(errors.errors().len(), 1, "{errors}");
    assert_eq!(errors.errors()[0].file, "i.yaml");
    assert!(errors.errors()[0].message.contains("8 MiB"), "{errors}");
}

#[test]
fn the_error_list_is_cut_after_one_hundred_entries() {
    let names = numbered(150);
    let files: Vec<(&str, &str)> = names
        .iter()
        .map(|name| (name.as_str(), INVALID_DOCUMENT))
        .collect();
    let errors = load_err(&files);
    assert_eq!(errors.errors().len(), 101, "{errors}");
    assert_eq!(errors.errors()[99].file, "f099.yaml");
    assert_eq!(errors.errors()[100].message, "50 more errors omitted");
    assert_eq!(errors.messages().len(), 101);
}

#[test]
fn parsing_one_file_stops_after_one_hundred_errors() {
    let many_empty_documents = "---\n".repeat(300);
    let errors = load_err(&[("a.yaml", &many_empty_documents)]);
    assert_eq!(errors.errors().len(), 101, "{errors}");
    assert_eq!(errors.errors()[99].document, Some(100));
    assert_eq!(errors.errors()[100].message, "1 more errors omitted");
}

#[cfg(unix)]
#[test]
fn symlinked_files_are_followed_and_broken_links_are_rejected() {
    use std::fs;
    use std::os::unix::fs::symlink;

    let first = "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n";
    let second = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: a@b.c, node: {}, login: x, expect: deny }\n";
    let direct = load_ok(&[("a.yaml", first), ("b.yml", second)]);

    let dir = tempfile::tempdir().expect("create temp dir");
    let generation = dir.path().join("..ts");
    fs::create_dir(&generation).expect("create generation dir");
    fs::write(generation.join("a.yaml"), first).expect("write a.yaml");
    fs::write(generation.join("b.yml"), second).expect("write b.yml");
    symlink("..ts", dir.path().join("..data")).expect("link data dir");
    symlink("..data/a.yaml", dir.path().join("a.yaml")).expect("link a.yaml");
    symlink("..data/b.yml", dir.path().join("b.yml")).expect("link b.yml");
    let linked = jaunt_policy::load_dir(dir.path()).expect("config map layout must load");
    assert_eq!(linked.hash(), direct.hash());
    assert_eq!(linked.tests().len(), 1);

    symlink("missing.yaml", dir.path().join("broken.yaml")).expect("link broken");
    symlink("loop-b.yaml", dir.path().join("loop-a.yaml")).expect("link loop a");
    symlink("loop-a.yaml", dir.path().join("loop-b.yaml")).expect("link loop b");
    let errors = jaunt_policy::load_dir(dir.path()).expect_err("broken links must be rejected");
    let mut rejected: Vec<&str> = errors.errors().iter().map(|e| e.file.as_str()).collect();
    rejected.sort_unstable();
    assert_eq!(rejected, ["broken.yaml", "loop-a.yaml", "loop-b.yaml"]);
    assert!(
        errors
            .errors()
            .iter()
            .all(|e| e.message.contains("cannot stat file"))
    );
}
