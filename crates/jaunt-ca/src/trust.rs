use ssh_key::sha2::{Digest, Sha256};
use ssh_key::{Algorithm, Fingerprint, HashAlg, PublicKey};

use crate::error::CaError;
use crate::fsutil::digest_hex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyRole {
    Active,
    Next,
    Previous,
}

impl KeyRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            KeyRole::Active => "active",
            KeyRole::Next => "next",
            KeyRole::Previous => "previous",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrustSet {
    keys: Vec<PublicKey>,
    active: usize,
    next: Option<usize>,
}

impl TrustSet {
    pub fn new(keys: Vec<PublicKey>, active: Fingerprint) -> Result<Self, CaError> {
        Self::with_next(keys, active, None)
    }

    pub fn with_next(
        keys: Vec<PublicKey>,
        active: Fingerprint,
        next: Option<Fingerprint>,
    ) -> Result<Self, CaError> {
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
        let next = next
            .map(|next| {
                let index = fingerprints
                    .iter()
                    .position(|fingerprint| *fingerprint == next)
                    .ok_or(CaError::NextKeyNotTrusted)?;
                if index == active {
                    return Err(CaError::NextKeyIsActive);
                }
                Ok(index)
            })
            .transpose()?;
        Ok(Self { keys, active, next })
    }

    pub fn active(&self) -> &PublicKey {
        &self.keys[self.active]
    }

    pub fn next(&self) -> Option<&PublicKey> {
        self.next.map(|index| &self.keys[index])
    }

    pub fn previous(&self) -> impl Iterator<Item = &PublicKey> {
        self.roles()
            .filter(|(role, _)| *role == KeyRole::Previous)
            .map(|(_, key)| key)
    }

    pub fn roles(&self) -> impl Iterator<Item = (KeyRole, &PublicKey)> {
        self.keys.iter().enumerate().map(|(index, key)| {
            let role = if index == self.active {
                KeyRole::Active
            } else if Some(index) == self.next {
                KeyRole::Next
            } else {
                KeyRole::Previous
            };
            (role, key)
        })
    }

    pub fn role(&self, fingerprint: &Fingerprint) -> Option<KeyRole> {
        self.roles()
            .find(|(_, key)| key.fingerprint(HashAlg::Sha256) == *fingerprint)
            .map(|(role, _)| role)
    }

    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }

    pub fn contains(&self, fingerprint: &Fingerprint) -> bool {
        self.keys
            .iter()
            .any(|key| key.fingerprint(HashAlg::Sha256) == *fingerprint)
    }

    pub fn set_id(&self) -> String {
        let mut digests: Vec<Vec<u8>> = self
            .keys
            .iter()
            .map(|key| key.fingerprint(HashAlg::Sha256).as_bytes().to_vec())
            .collect();
        digests.sort_unstable();
        let mut hasher = Sha256::new();
        for digest in &digests {
            hasher.update(digest);
        }
        digest_hex(&hasher.finalize())
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

    use ssh_key::sha2::{Digest, Sha256};

    use super::{KeyRole, TrustSet};
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

    #[test]
    fn roles_follow_the_active_and_next_fingerprints() {
        let (active, next, previous) = (subject_key(), subject_key(), subject_key());
        let set = TrustSet::with_next(
            vec![previous.clone(), next.clone(), active.clone()],
            fingerprint(&active),
            Some(fingerprint(&next)),
        )
        .unwrap();
        assert_eq!(set.active().key_data(), active.key_data());
        assert_eq!(set.next().unwrap().key_data(), next.key_data());
        let previous_keys: Vec<_> = set.previous().collect();
        assert_eq!(previous_keys.len(), 1);
        assert_eq!(previous_keys[0].key_data(), previous.key_data());
        assert_eq!(set.role(&fingerprint(&active)), Some(KeyRole::Active));
        assert_eq!(set.role(&fingerprint(&next)), Some(KeyRole::Next));
        assert_eq!(set.role(&fingerprint(&previous)), Some(KeyRole::Previous));
        assert_eq!(set.role(&fingerprint(&subject_key())), None);
        assert_eq!(set.keys().len(), 3);

        let without_next = TrustSet::new(vec![active.clone()], fingerprint(&active)).unwrap();
        assert!(without_next.next().is_none());
        assert_eq!(without_next.previous().count(), 0);
    }

    #[test]
    fn next_must_be_a_trusted_key_other_than_the_active_one() {
        let (active, stranger) = (subject_key(), subject_key());
        assert!(matches!(
            TrustSet::with_next(
                vec![active.clone()],
                fingerprint(&active),
                Some(fingerprint(&stranger))
            ),
            Err(CaError::NextKeyNotTrusted)
        ));
        assert!(matches!(
            TrustSet::with_next(
                vec![active.clone()],
                fingerprint(&active),
                Some(fingerprint(&active))
            ),
            Err(CaError::NextKeyIsActive)
        ));
    }

    #[test]
    fn set_id_hashes_the_sorted_fingerprints_and_ignores_order_and_roles() {
        let (first, second, third) = (subject_key(), subject_key(), subject_key());
        let forward = TrustSet::with_next(
            vec![first.clone(), second.clone()],
            fingerprint(&first),
            Some(fingerprint(&second)),
        )
        .unwrap();
        let backward =
            TrustSet::new(vec![second.clone(), first.clone()], fingerprint(&second)).unwrap();

        let mut digests = [&first, &second].map(|key| fingerprint(key).as_bytes().to_vec());
        digests.sort();
        let expected: String = Sha256::digest(digests.concat())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();

        assert_eq!(forward.set_id(), expected);
        assert_eq!(forward.set_id(), forward.set_id());
        assert_eq!(backward.set_id(), expected);
        assert_eq!(expected.len(), 64);
        let grown = TrustSet::new(
            vec![first.clone(), second.clone(), third],
            fingerprint(&first),
        )
        .unwrap();
        let shrunk = TrustSet::new(vec![first.clone()], fingerprint(&first)).unwrap();
        assert_ne!(grown.set_id(), expected);
        assert_ne!(shrunk.set_id(), expected);
        assert_ne!(grown.set_id(), shrunk.set_id());
    }
}
