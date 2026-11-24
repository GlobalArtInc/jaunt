use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

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

#[derive(Debug)]
struct Shared {
    current: RwLock<Arc<PolicySet>>,
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
                current: RwLock::new(Arc::new(PolicySet::empty())),
                reload: Mutex::new(()),
            }),
        }
    }

    pub fn snapshot(&self) -> Arc<PolicySet> {
        let guard = self
            .shared
            .current
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    pub fn reload(&self, dir: &Path) -> ReloadOutcome {
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
                if set.is_empty() && !guard.is_empty() {
                    return ReloadOutcome {
                        applied: false,
                        unchanged: false,
                        hash: None,
                        input_hash: Some(hash),
                        errors: vec![EMPTY_RELOAD_REFUSED.to_owned()],
                    };
                }
                let unchanged = guard.hash() == hash;
                *guard = Arc::new(set);
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
