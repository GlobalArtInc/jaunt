use std::cell::RefCell;

use ssh_key::public::KeyData;
use ssh_key::{PublicKey, Signature};

use crate::error::CaError;
use crate::kind::CaKind;

pub trait Signer: Send + Sync {
    fn kind(&self) -> CaKind;

    fn public_key(&self) -> &PublicKey;

    fn try_sign(&self, msg: &[u8]) -> Result<Signature, CaError>;
}

pub(crate) struct SignerAdapter<'a> {
    inner: &'a dyn Signer,
    failure: RefCell<Option<CaError>>,
}

impl<'a> SignerAdapter<'a> {
    pub(crate) fn new(inner: &'a dyn Signer) -> Self {
        Self {
            inner,
            failure: RefCell::new(None),
        }
    }

    pub(crate) fn take_failure(&self) -> Option<CaError> {
        self.failure.borrow_mut().take()
    }
}

impl signature::Signer<Signature> for SignerAdapter<'_> {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        self.inner.try_sign(msg).map_err(|err| {
            *self.failure.borrow_mut() = Some(err);
            signature::Error::new()
        })
    }
}

impl From<&SignerAdapter<'_>> for KeyData {
    fn from(adapter: &SignerAdapter<'_>) -> KeyData {
        adapter.inner.public_key().key_data().clone()
    }
}
