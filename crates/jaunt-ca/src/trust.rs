use ssh_key::{Algorithm, Fingerprint, HashAlg, PublicKey};

use crate::error::CaError;

#[derive(Clone, Debug)]
pub struct TrustSet {
    keys: Vec<PublicKey>,
    active: usize,
}

impl TrustSet {
    pub fn new(keys: Vec<PublicKey>, active: Fingerprint) -> Result<Self, CaError> {
        if keys.iter().any(|key| key.algorithm() != Algorithm::Ed25519) {
            return Err(CaError::UnsupportedKeyAlgorithm);
        }
        let keys: Vec<PublicKey> = keys
            .into_iter()
            .map(|key| PublicKey::from(key.key_data().clone()))
            .collect();
        let fingerprints: Vec<Fingerprint> = keys
            .iter()
            .map(|key| key.fingerprint(HashAlg::Sha256))
            .collect();
        for (index, fingerprint) in fingerprints.iter().enumerate() {
            if fingerprints[..index].contains(fingerprint) {
                return Err(CaError::DuplicateTrustedKey);
            }
        }
        let active = fingerprints
            .iter()
            .position(|fingerprint| *fingerprint == active)
            .ok_or(CaError::ActiveKeyNotTrusted)?;
        Ok(Self { keys, active })
    }

    pub fn active(&self) -> &PublicKey {
        &self.keys[self.active]
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.keys
            .iter()
            .any(|key| key.fingerprint(HashAlg::Sha256) == *fingerprint)
    }

    pub fn to_authorized_lines(&self) -> Result<Vec<String>, CaError> {
        self.keys
            .iter()
            .map(|key| key.to_openssh().map_err(CaError::SshKey))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::public::{KeyData, SkEd25519};
    use ssh_key::{Algorithm, HashAlg, PublicKey};

    use super::TrustSet;
    use crate::error::CaError;
    use crate::test_support::subject_key;

    fn fingerprint(key: &PublicKey) -> ssh_key::Fingerprint {
        key.fingerprint(HashAlg::Sha256)
    }

    #[test]
    fn active_key_must_be_in_the_set() {
        let (first, second, stranger) = (subject_key(), subject_key(), subject_key());
        let set = TrustSet::new(vec![first.clone(), second.clone()], fingerprint(&second)).unwrap();
        assert_eq!(set.active().key_data(), second.key_data());
        assert!(set.contains(&fingerprint(&first)));
        assert!(!set.contains(&fingerprint(&stranger)));
        assert!(matches!(
            TrustSet::new(vec![first, second], fingerprint(&stranger)),
            Err(CaError::ActiveKeyNotTrusted)
        ));
        assert!(matches!(
            TrustSet::new(Vec::new(), fingerprint(&stranger)),
            Err(CaError::ActiveKeyNotTrusted)
        ));
    }

    #[test]
    fn only_ed25519_keys_are_accepted() {
        let good = subject_key();
        let ed25519 = *good.key_data().ed25519().unwrap();
        let security_key = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")));
        assert_eq!(security_key.algorithm(), Algorithm::SkEd25519);
        assert!(matches!(
            TrustSet::new(vec![good.clone(), security_key.clone()], fingerprint(&good)),
            Err(CaError::UnsupportedKeyAlgorithm)
        ));
        assert!(matches!(
            TrustSet::new(vec![security_key.clone()], fingerprint(&security_key)),
            Err(CaError::UnsupportedKeyAlgorithm)
        ));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let key = subject_key();
        let mut commented = key.clone();
        commented.set_comment("same key, other comment");
        assert!(matches!(
            TrustSet::new(vec![key.clone(), commented], fingerprint(&key)),
            Err(CaError::DuplicateTrustedKey)
        ));
    }

    #[test]
    fn authorized_lines_hold_one_key_per_line() {
        let (first, second) = (subject_key(), subject_key());
        let set = TrustSet::new(vec![first.clone(), second.clone()], fingerprint(&first)).unwrap();
        let lines = set.to_authorized_lines().unwrap();
        assert_eq!(lines.len(), 2);
        for (line, key) in lines.iter().zip([&first, &second]) {
            assert!(line.starts_with("ssh-ed25519 "));
            assert!(!line.contains('\n'));
            assert_eq!(
                PublicKey::from_openssh(line).unwrap().key_data(),
                key.key_data()
            );
        }
    }
}
