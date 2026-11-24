#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tempfile::TempDir;

static DIR: OnceLock<TempDir> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let dir = DIR.get_or_init(|| tempfile::tempdir().expect("a scratch directory"));
    std::fs::write(dir.path().join("policy.yaml"), data).expect("the policy file is written");
    match jaunt_policy::load_dir(dir.path()) {
        Ok(set) => assert!(!set.hash().is_empty()),
        Err(errors) => assert!(!errors.errors().is_empty()),
    }
});
