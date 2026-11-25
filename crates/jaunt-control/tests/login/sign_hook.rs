use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use jaunt_ca::ssh_key::{PublicKey, Signature};
use jaunt_ca::{CaError, CaKind, Signer};

type Armed = Box<dyn FnOnce() + Send>;

#[derive(Clone, Default)]
pub struct SignHook {
    armed: Arc<Mutex<Option<Armed>>>,
    fired: Arc<AtomicBool>,
}

impl SignHook {
    pub fn arm(&self, action: impl FnOnce() + Send + 'static) {
        *self.armed.lock().unwrap() = Some(Box::new(action));
    }

    pub fn fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }

    pub fn wrap(self, inner: Arc<dyn Signer>) -> Arc<dyn Signer> {
        Arc::new(HookedSigner { inner, hook: self })
    }

    fn fire(&self) {
        let action = self.armed.lock().unwrap().take();
        if let Some(action) = action {
            action();
            self.fired.store(true, Ordering::SeqCst);
        }
    }
}

struct HookedSigner {
    inner: Arc<dyn Signer>,
    hook: SignHook,
}

impl Signer for HookedSigner {
    fn kind(&self) -> CaKind {
        self.inner.kind()
    }

    fn public_key(&self) -> &PublicKey {
        self.inner.public_key()
    }

    fn try_sign(&self, msg: &[u8]) -> Result<Signature, CaError> {
        self.hook.fire();
        self.inner.try_sign(msg)
    }
}
