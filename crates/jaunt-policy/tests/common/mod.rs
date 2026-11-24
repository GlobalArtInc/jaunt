use std::fs;

use jaunt_policy::{LoadErrors, PolicySet, load_dir};
use tempfile::TempDir;

pub fn write_dir(files: &[(&str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().expect("create temp dir");
    for (name, content) in files {
        fs::write(dir.path().join(name), content).expect("write policy file");
    }
    dir
}

pub fn load_ok(files: &[(&str, &str)]) -> PolicySet {
    let dir = write_dir(files);
    load_dir(dir.path()).expect("policy set must load")
}

pub fn load_err(files: &[(&str, &str)]) -> LoadErrors {
    let dir = write_dir(files);
    match load_dir(dir.path()) {
        Ok(_) => panic!("policy set must be rejected"),
        Err(errors) => errors,
    }
}
