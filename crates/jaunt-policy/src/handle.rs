use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::SystemTime;

use crate::loader::load_dir;
use crate::policy::PolicySet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub applied: bool,
    pub unchanged: bool,
    pub hash: Option<String>,
    pub input_hash: Option<String>,
    pub errors: Vec<String>,
}

const EMPTY_RELOAD_REFUSED: &str =
    "refusing to replace a non-empty policy set with an empty one; the last valid set stays active";

#[derive(Debug, Clone)]
pub struct LoadedPolicy {
    pub set: Arc<PolicySet>,
    pub loaded_at: Option<SystemTime>,
}

#[derive(Debug)]
struct Shared {
    current: RwLock<LoadedPolicy>,
    reload: Mutex<()>,
}

#[derive(Debug, Clone)]
pub struct PolicyHandle {
    shared: Arc<Shared>,
}

impl PolicyHandle {
    pub fn empty() -> Self {
        PolicyHandle {
            shared: Arc::new(Shared {
                current: RwLock::new(LoadedPolicy {
                    set: Arc::new(PolicySet::empty()),
                    loaded_at: None,
                }),
                reload: Mutex::new(()),
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<PolicySet> {
        Arc::clone(&self.loaded().set)
    }

    pub fn loaded(&self) -> LoadedPolicy {
        self.shared
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn reload(&self, dir: &Path) -> ReloadOutcome {
        self.reload_at(dir, SystemTime::now())
    }

    pub fn reload_at(&self, dir: &Path, now: SystemTime) -> ReloadOutcome {
        let _serialized = self
            .shared
            .reload
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match load_dir(dir) {
            Ok(set) => {
                let hash = set.hash().to_owned();
                let mut guard = self
                    .shared
                    .current
                    .write()
                    .unwrap_or_else(PoisonError::into_inner);
                if set.is_empty() && !guard.set.is_empty() {
                    return ReloadOutcome {
                        applied: false,
                        unchanged: false,
                        hash: None,
                        input_hash: Some(hash),
                        errors: vec![EMPTY_RELOAD_REFUSED.to_owned()],
                    };
                }
                let unchanged = guard.set.hash() == hash;
                let loaded_at = match guard.loaded_at {
                    Some(previous) if unchanged => previous,
                    _ => now,
                };
                *guard = LoadedPolicy {
                    set: Arc::new(set),
                    loaded_at: Some(loaded_at),
                };
                ReloadOutcome {
                    applied: true,
                    unchanged,
                    hash: Some(hash.clone()),
                    input_hash: Some(hash),
                    errors: Vec::new(),
                }
            }
            Err(errors) => ReloadOutcome {
                applied: false,
                unchanged: false,
                hash: None,
                input_hash: errors.input_hash().map(str::to_owned),
                errors: errors.messages(),
            },
        }
    }
}
