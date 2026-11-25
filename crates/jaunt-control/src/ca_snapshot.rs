use std::fmt;
use std::sync::Arc;

use jaunt_ca::ssh_key::PublicKey;
use jaunt_ca::{CaError, CaKind, KeyRole, Signer, TrustSet, fingerprint_hex};

use crate::error::ControlError;

pub struct CaSnapshot {
    user_signer: Arc<dyn Signer>,
    user_trust: TrustSet,
    host_signer: Arc<dyn Signer>,
    host_trust: TrustSet,
    user_trust_id: String,
    host_trust_id: String,
    user_ca_keys: Vec<String>,
    host_ca_keys: Vec<String>,
    host_ca_active: String,
}

impl CaSnapshot {
    pub fn new(
        user_signer: Arc<dyn Signer>,
        user_trust: TrustSet,
        host_signer: Arc<dyn Signer>,
        host_trust: TrustSet,
    ) -> Result<CaSnapshot, ControlError> {
        if user_signer.kind() != CaKind::User {
            return Err(ControlError::NotUserAuthority);
        }
        if !signs_for(user_signer.as_ref(), &user_trust) {
            return Err(ControlError::UserAuthorityNotTrusted);
        }
        if host_signer.kind() != CaKind::Host {
            return Err(ControlError::NotHostAuthority);
        }
        if !signs_for(host_signer.as_ref(), &host_trust) {
            return Err(ControlError::HostAuthorityNotTrusted);
        }
        let user_ca_keys = active_first(&user_trust).map_err(ControlError::UserKeys)?;
        let host_ca_keys = by_role(&host_trust).map_err(ControlError::HostKeys)?;
        let host_ca_active = openssh(host_trust.active()).map_err(ControlError::HostKeys)?;
        Ok(CaSnapshot {
            user_trust_id: user_trust.set_id(),
            host_trust_id: host_trust.set_id(),
            user_signer,
            user_trust,
            host_signer,
            host_trust,
            user_ca_keys,
            host_ca_keys,
            host_ca_active,
        })
    }

    pub fn user_signer(&self) -> &Arc<dyn Signer> {
        &self.user_signer
    }

    pub fn user_trust(&self) -> &TrustSet {
        &self.user_trust
    }

    pub fn host_signer(&self) -> &Arc<dyn Signer> {
        &self.host_signer
    }

    pub fn host_trust(&self) -> &TrustSet {
        &self.host_trust
    }

    pub fn user_trust_id(&self) -> &str {
        &self.user_trust_id
    }

    pub fn host_trust_id(&self) -> &str {
        &self.host_trust_id
    }

    pub(crate) fn user_ca_keys(&self) -> &[String] {
        &self.user_ca_keys
    }

    pub(crate) fn host_ca_keys(&self) -> &[String] {
        &self.host_ca_keys
    }

    pub(crate) fn host_ca_active(&self) -> &str {
        &self.host_ca_active
    }
}

impl fmt::Debug for CaSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaSnapshot")
            .field(
                "user_signer",
                &fingerprint_hex(self.user_signer.public_key()),
            )
            .field("user_trust_id", &self.user_trust_id)
            .field(
                "host_signer",
                &fingerprint_hex(self.host_signer.public_key()),
            )
            .field("host_trust_id", &self.host_trust_id)
            .finish_non_exhaustive()
    }
}

fn signs_for(signer: &dyn Signer, trust: &TrustSet) -> bool {
    trust.active().key_data() == signer.public_key().key_data()
}

fn openssh(key: &PublicKey) -> Result<String, CaError> {
    key.to_openssh().map_err(CaError::SshKey)
}

fn active_first(trust: &TrustSet) -> Result<Vec<String>, CaError> {
    let lines = trust.to_authorized_lines()?;
    let active = trust.active().key_data();
    let (first, rest): (Vec<_>, Vec<_>) = trust
        .keys()
        .iter()
        .zip(lines)
        .partition(|(key, _)| key.key_data() == active);
    Ok(first
        .into_iter()
        .chain(rest)
        .map(|(_, line)| line)
        .collect())
}

fn by_role(trust: &TrustSet) -> Result<Vec<String>, CaError> {
    let mut lines = Vec::with_capacity(trust.keys().len());
    for role in [KeyRole::Active, KeyRole::Next, KeyRole::Previous] {
        for (_, key) in trust.roles().filter(|(found, _)| *found == role) {
            lines.push(openssh(key)?);
        }
    }
    Ok(lines)
}
