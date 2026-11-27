use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Fingerprint, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};

use crate::error::CaError;
use crate::fsutil::{
    ensure_private_dir, exists, fingerprint_from_hex, fingerprint_hex, read_limited, write_new,
    write_new_with,
};
use crate::identity::{AgeIdentity, AgeRecipient, encrypt};
use crate::kind::CaKind;
use crate::signer::Signer;
use crate::trust::TrustSet;
use crate::x509::{ClientCa, IssuedCertificate};

pub(crate) const ACTIVE_FILE: &str = "active";
pub(crate) const NEXT_FILE: &str = "next";
pub(crate) const RETIRED_DIR: &str = "retired";
pub(crate) const PUBLIC_SUFFIX: &str = ".pub";
pub(crate) const ENCRYPTED_SUFFIX: &str = ".age";
pub(crate) const ROOT_SUFFIX: &str = ".root.der";

const MAX_ACTIVE_LEN: u64 = 128;
pub(crate) const MAX_ROOT_LEN: u64 = 16 * 1024;
const MAX_PUBLIC_LEN: u64 = 4096;
const MAX_ENCRYPTED_LEN: u64 = 64 * 1024;
pub(crate) const MAX_PRIVATE_LEN: usize = 8 * 1024;

pub struct FileBackend {
    kind: CaKind,
    private_key: PrivateKey,
    public_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct SlotListing {
    pub trust: TrustSet,
    pub retired: Vec<String>,
    pub stray: Vec<String>,
}

impl FileBackend {
    pub fn is_initialized(root: &Path, kind: CaKind) -> Result<bool, CaError> {
        exists(&kind_dir(root, kind).join(ACTIVE_FILE))
    }

    pub fn init(root: &Path, kind: CaKind, recipient: &AgeRecipient) -> Result<PublicKey, CaError> {
        Self::init_with(root, kind, recipient, &|_| Ok(()))
    }

    fn init_with(
        root: &Path,
        kind: CaKind,
        recipient: &AgeRecipient,
        after_link: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<PublicKey, CaError> {
        if kind.is_x509_client() {
            return Err(CaError::RootRequired(kind));
        }
        let dir = kind_dir(root, kind);
        if exists(&dir.join(ACTIVE_FILE))? {
            return Err(CaError::AlreadyInitialized(kind));
        }
        ensure_private_dir(root, false).map_err(CaError::io("create directory", root))?;
        ensure_private_dir(&dir, true).map_err(CaError::io("create directory", &dir))?;
        let (public_key, _) = write_slot(&dir, kind, recipient, None, after_link)?;
        Ok(public_key)
    }

    pub(crate) fn generate(kind: CaKind) -> Result<FileBackend, CaError> {
        let private_key =
            PrivateKey::random(&mut OsRng, Algorithm::Ed25519).map_err(CaError::SshKey)?;
        let public_key = PublicKey::from(private_key.public_key().key_data().clone());
        Ok(FileBackend {
            kind,
            private_key,
            public_key,
        })
    }

    pub(crate) fn private_pem(&self) -> Result<zeroize::Zeroizing<String>, CaError> {
        self.private_key
            .to_openssh(LineEnding::LF)
            .map_err(CaError::SshKey)
    }

    pub(crate) fn root_certificate(
        &self,
        root_at: Option<SystemTime>,
    ) -> Result<Option<IssuedCertificate>, CaError> {
        match (self.kind.is_x509_client(), root_at) {
            (true, Some(now)) => ClientCa::create_root(self, now).map(Some),
            (true, None) => Err(CaError::RootRequired(self.kind)),
            (false, None) => Ok(None),
            (false, Some(_)) => Err(CaError::NotAClientAuthority(self.kind)),
        }
    }

    pub fn load(
        root: &Path,
        kind: CaKind,
        identity: &AgeIdentity,
    ) -> Result<(TrustSet, FileBackend), CaError> {
        let dir = kind_dir(root, kind);
        let (active_hex, trust) = read_trust(&dir, kind)?;

        let private_key = read_private_key(&dir, &active_hex, identity)?;
        let public_key = trust.active().clone();
        Ok((
            trust,
            FileBackend {
                kind,
                private_key,
                public_key,
            },
        ))
    }

    pub fn load_with_next(
        root: &Path,
        kind: CaKind,
        identity: &AgeIdentity,
    ) -> Result<(TrustSet, FileBackend), CaError> {
        let (trust, backend) = Self::load(root, kind, identity)?;
        if let Some(next) = trust.next() {
            let dir = kind_dir(root, kind);
            read_private_key(&dir, &fingerprint_hex(next), identity).map(|_| ())?;
        }
        Ok((trust, backend))
    }

    pub fn read_active(root: &Path, kind: CaKind) -> Result<Fingerprint, CaError> {
        read_active_key(&kind_dir(root, kind), kind).map(|(_, fingerprint)| fingerprint)
    }

    pub fn read_slot(root: &Path, kind: CaKind) -> Result<SlotListing, CaError> {
        let dir = kind_dir(root, kind);
        let (_, trust) = read_trust(&dir, kind)?;
        let trusted: Vec<String> = trust.keys().iter().map(fingerprint_hex).collect();
        let retired = list_fingerprints(&dir.join(RETIRED_DIR), PUBLIC_SUFFIX)?;
        let stray = list_fingerprints(&dir, ENCRYPTED_SUFFIX)?
            .into_iter()
            .filter(|hex| !trusted.contains(hex))
            .collect();
        Ok(SlotListing {
            trust,
            retired,
            stray,
        })
    }
}

impl FileBackend {
    pub fn store_root_certificate(root: &Path, der: &[u8]) -> Result<(), CaError> {
        if der.is_empty() || der.len() as u64 > MAX_ROOT_LEN {
            return Err(CaError::InvalidRootCertificate {
                reason: "size is out of range",
            });
        }
        let dir = kind_dir(root, CaKind::Internal);
        let (active_hex, _) = read_active_key(&dir, CaKind::Internal)?;
        let path = dir.join(format!("{active_hex}{ROOT_SUFFIX}"));
        match write_new(&path, der) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                Err(CaError::RootCertificateExists)
            }
            Err(err) => Err(CaError::io("write", &path)(err)),
        }
    }

    pub fn load_root_certificate(root: &Path) -> Result<Vec<u8>, CaError> {
        let dir = kind_dir(root, CaKind::Internal);
        let (active_hex, _) = read_active_key(&dir, CaKind::Internal)?;
        let path = dir.join(format!("{active_hex}{ROOT_SUFFIX}"));
        if !exists(&path)? {
            return Err(CaError::RootCertificateMissing);
        }
        Ok(read_limited(&path, MAX_ROOT_LEN)?.to_vec())
    }
}

impl Signer for FileBackend {
    fn kind(&self) -> CaKind {
        self.kind
    }

    fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    fn try_sign(&self, msg: &[u8]) -> Result<Signature, CaError> {
        signature::Signer::try_sign(&self.private_key, msg).map_err(|_| CaError::Sign)
    }
}

impl fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = self.public_key.fingerprint(HashAlg::Sha256);
        f.debug_struct("FileBackend")
            .field("kind", &self.kind)
            .field("fingerprint", &format_args!("{fingerprint}"))
            .finish_non_exhaustive()
    }
}

pub(crate) fn kind_dir(root: &Path, kind: CaKind) -> PathBuf {
    root.join(kind.as_str())
}

pub(crate) struct KeyFiles<'a> {
    pub(crate) hex: &'a str,
    pub(crate) encrypted: &'a [u8],
    pub(crate) root: Option<&'a [u8]>,
    pub(crate) public_line: &'a [u8],
    pub(crate) pointer: &'static str,
    pub(crate) pointer_taken: CaError,
}

pub(crate) fn write_slot(
    dir: &Path,
    kind: CaKind,
    recipient: &AgeRecipient,
    root_at: Option<SystemTime>,
    after_link: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<(PublicKey, Option<IssuedCertificate>), CaError> {
    let backend = FileBackend::generate(kind)?;
    let root = backend.root_certificate(root_at)?;
    let hex = fingerprint_hex(&backend.public_key);
    let pem = backend.private_pem()?;
    let encrypted = encrypt(recipient, pem.as_bytes())?;
    let public_line = format!(
        "{}\n",
        backend.public_key.to_openssh().map_err(CaError::SshKey)?
    );

    let mut created: Vec<PathBuf> = Vec::new();
    let outcome = write_key_files(
        dir,
        KeyFiles {
            hex: &hex,
            encrypted: &encrypted,
            root: root.as_ref().map(|root| root.certificate_der.as_slice()),
            public_line: public_line.as_bytes(),
            pointer: ACTIVE_FILE,
            pointer_taken: CaError::AlreadyInitialized(kind),
        },
        after_link,
        &mut created,
    );
    if let Err(err) = outcome {
        for path in &created {
            drop(fs::remove_file(path));
        }
        return Err(err);
    }
    Ok((backend.public_key.clone(), root))
}

pub(crate) fn write_key_files(
    dir: &Path,
    files: KeyFiles<'_>,
    after_link: &dyn Fn(&Path) -> io::Result<()>,
    created: &mut Vec<PathBuf>,
) -> Result<(), CaError> {
    let encrypted_path = dir.join(format!("{}{ENCRYPTED_SUFFIX}", files.hex));
    write_new_with(&encrypted_path, files.encrypted, after_link)
        .map_err(CaError::io("write", &encrypted_path))?;
    created.push(encrypted_path);

    if let Some(root) = files.root {
        let root_path = dir.join(format!("{}{ROOT_SUFFIX}", files.hex));
        write_new_with(&root_path, root, after_link).map_err(CaError::io("write", &root_path))?;
        created.push(root_path);
    }

    let public_path = dir.join(format!("{}{PUBLIC_SUFFIX}", files.hex));
    write_new_with(&public_path, files.public_line, after_link)
        .map_err(CaError::io("write", &public_path))?;
    created.push(public_path);

    let pointer_path = dir.join(files.pointer);
    match write_new_with(
        &pointer_path,
        format!("{}\n", files.hex).as_bytes(),
        after_link,
    ) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Err(files.pointer_taken),
        Err(err) => Err(CaError::io("write", &pointer_path)(err)),
    }
}

pub(crate) fn corrupt(path: &Path, reason: &'static str) -> CaError {
    CaError::CorruptStore {
        path: path.to_path_buf(),
        reason,
    }
}

pub(crate) fn read_trust(dir: &Path, kind: CaKind) -> Result<(String, TrustSet), CaError> {
    let (active_hex, active_fingerprint) = read_active_key(dir, kind)?;
    let next = read_next_key(dir)?.filter(|next| *next != active_fingerprint);
    let trust = TrustSet::with_next(read_public_keys(dir)?, active_fingerprint, next)?;
    Ok((active_hex, trust))
}

fn read_active_key(dir: &Path, kind: CaKind) -> Result<(String, Fingerprint), CaError> {
    let active_path = dir.join(ACTIVE_FILE);
    if !exists(&active_path)? {
        return Err(CaError::NotInitialized(kind));
    }
    let active_hex = read_pointer(&active_path, "active file is not text")?;
    let fingerprint = fingerprint_from_hex(&active_hex)
        .ok_or_else(|| corrupt(&active_path, "active file does not hold a key fingerprint"))?;
    Ok((active_hex, fingerprint))
}

fn read_next_key(dir: &Path) -> Result<Option<Fingerprint>, CaError> {
    let next_path = dir.join(NEXT_FILE);
    if !exists(&next_path)? {
        return Ok(None);
    }
    let next_hex = read_pointer(&next_path, "next file is not text")?;
    fingerprint_from_hex(&next_hex)
        .map(Some)
        .ok_or_else(|| corrupt(&next_path, "next file does not hold a key fingerprint"))
}

fn read_pointer(path: &Path, not_text: &'static str) -> Result<String, CaError> {
    let bytes = read_limited(path, MAX_ACTIVE_LEN)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| corrupt(path, not_text))?;
    Ok(text.strip_suffix('\n').unwrap_or(text).to_owned())
}

pub(crate) fn list_fingerprints(dir: &Path, suffix: &str) -> Result<Vec<String>, CaError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(CaError::io("read directory", dir)(err)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(CaError::io("read directory", dir))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if let Some(stem) = name.strip_suffix(suffix)
            && fingerprint_from_hex(stem).is_some()
        {
            found.push(stem.to_owned());
        }
    }
    found.sort();
    Ok(found)
}

fn read_public_keys(dir: &Path) -> Result<Vec<PublicKey>, CaError> {
    let entries = fs::read_dir(dir).map_err(CaError::io("read directory", dir))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(CaError::io("read directory", dir))?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.ends_with(PUBLIC_SUFFIX) {
            names.push(name);
        }
    }
    names.sort();

    let mut keys = Vec::with_capacity(names.len());
    for name in names {
        let path = dir.join(&name);
        let stem = name.strip_suffix(PUBLIC_SUFFIX).unwrap_or(&name);
        if fingerprint_from_hex(stem).is_none() {
            return Err(corrupt(&path, "public key file name is not a fingerprint"));
        }
        let bytes = read_limited(&path, MAX_PUBLIC_LEN)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| corrupt(&path, "public key file is not text"))?;
        let key = PublicKey::from_openssh(text)
            .map_err(|_| corrupt(&path, "public key file is not an OpenSSH public key"))?;
        if fingerprint_hex(&key) != stem {
            return Err(corrupt(&path, "public key does not match its file name"));
        }
        keys.push(key);
    }
    Ok(keys)
}

pub(crate) fn read_private_key(
    dir: &Path,
    active_hex: &str,
    identity: &AgeIdentity,
) -> Result<PrivateKey, CaError> {
    let path = dir.join(format!("{active_hex}{ENCRYPTED_SUFFIX}"));
    let ciphertext = read_limited(&path, MAX_ENCRYPTED_LEN)?;
    let plaintext = identity.decrypt(&ciphertext, MAX_PRIVATE_LEN)?;
    let key = PrivateKey::from_openssh(&*plaintext)
        .map_err(|_| corrupt(&path, "decrypted key is not an OpenSSH private key"))?;
    if key.is_encrypted() || key.algorithm() != Algorithm::Ed25519 {
        return Err(corrupt(&path, "decrypted key is not an Ed25519 key"));
    }
    if fingerprint_hex(key.public_key()) != active_hex {
        return Err(corrupt(&path, "decrypted key does not match its file name"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::time::{Duration, UNIX_EPOCH};

    use ssh_key::public::{KeyData, SkEd25519};
    use ssh_key::sha2::{Digest, Sha256};
    use ssh_key::{HashAlg, LineEnding, PublicKey};

    use super::FileBackend;
    use crate::cert::{UserCertParams, sign_user_certificate};
    use crate::error::CaError;
    use crate::fsutil::fingerprint_hex;
    use crate::identity::AgeIdentity;
    use crate::kind::CaKind;
    use crate::signer::Signer;
    use crate::test_support::{authority, subject_key};

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn backend_is_send_and_sync() {
        fn assert_signer<T: Signer + Send + Sync>() {}
        assert_signer::<FileBackend>();
    }

    #[test]
    fn signing_key_material_is_wiped_on_drop() {
        fn assert_wiped<T: zeroize::ZeroizeOnDrop>() {}
        assert_wiped::<ed25519_dalek::SigningKey>();
    }

    #[test]
    fn init_load_sign_verify_cycle() {
        let authority = authority(CaKind::User);
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let cert = sign_user_certificate(
            &authority.backend,
            UserCertParams {
                subject_public_key: subject_key(),
                user_id: crate::Uuid::from_u128(0x1234),
                email: "alice@example.com".to_owned(),
                serial: 1,
                validity: Duration::from_secs(3600),
            },
            now,
        )
        .unwrap();
        let trusted = authority.trust.active().fingerprint(HashAlg::Sha256);
        assert!(cert.validate_at(1_700_000_000, [&trusted]).is_ok());
        assert_eq!(authority.backend.kind(), CaKind::User);
        assert_eq!(
            authority.backend.public_key().key_data(),
            authority.trust.active().key_data()
        );
    }

    #[test]
    fn layout_follows_the_fingerprint_of_the_wire_format() {
        let authority = authority(CaKind::Host);
        let dir = authority.dir.path().join("host");
        let wire = authority.trust.active().to_bytes().unwrap();
        let hex: String = Sha256::digest(&wire)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut expected = vec![
            "active".to_owned(),
            format!("{hex}.age"),
            format!("{hex}.pub"),
        ];
        expected.sort();
        assert_eq!(file_names(&dir), expected);
        assert_eq!(
            fs::read_to_string(dir.join("active")).unwrap(),
            format!("{hex}\n")
        );
        let line = fs::read_to_string(dir.join(format!("{hex}.pub"))).unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(
            PublicKey::from_openssh(&line).unwrap().key_data(),
            authority.trust.active().key_data()
        );
        let encrypted = fs::read(dir.join(format!("{hex}.age"))).unwrap();
        assert!(encrypted.starts_with(b"age-encryption.org/v1\n"));
    }

    #[test]
    fn user_host_and_internal_authorities_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let identity = AgeIdentity::generate();
        let user = FileBackend::init(dir.path(), CaKind::User, &identity.recipient()).unwrap();
        let host = FileBackend::init(dir.path(), CaKind::Host, &identity.recipient()).unwrap();
        let internal =
            FileBackend::init(dir.path(), CaKind::Internal, &identity.recipient()).unwrap();
        assert_ne!(user.key_data(), host.key_data());
        assert_ne!(user.key_data(), internal.key_data());
        assert_ne!(host.key_data(), internal.key_data());
        let (user_trust, _) = FileBackend::load(dir.path(), CaKind::User, &identity).unwrap();
        let (host_trust, _) = FileBackend::load(dir.path(), CaKind::Host, &identity).unwrap();
        let (internal_trust, backend) =
            FileBackend::load(dir.path(), CaKind::Internal, &identity).unwrap();
        assert_eq!(user_trust.keys().len(), 1);
        assert_eq!(user_trust.active().key_data(), user.key_data());
        assert_eq!(host_trust.active().key_data(), host.key_data());
        assert_eq!(internal_trust.active().key_data(), internal.key_data());
        assert_eq!(backend.kind(), CaKind::Internal);
        assert!(dir.path().join("internal").join("active").exists());
    }

    #[test]
    fn root_certificate_is_stored_beside_the_internal_key_and_never_replaced() {
        let authority = authority(CaKind::Internal);
        let root = authority.dir.path();
        let dir = root.join("internal");
        let hex = fingerprint_hex(authority.trust.active());
        assert!(matches!(
            FileBackend::load_root_certificate(root),
            Err(CaError::RootCertificateMissing)
        ));

        FileBackend::store_root_certificate(root, b"root der").unwrap();
        let mut expected = vec![
            "active".to_owned(),
            format!("{hex}.age"),
            format!("{hex}.pub"),
            format!("{hex}.root.der"),
        ];
        expected.sort();
        assert_eq!(file_names(&dir), expected);
        assert_eq!(
            FileBackend::load_root_certificate(root).unwrap(),
            b"root der"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.join(format!("{hex}.root.der"));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        assert!(matches!(
            FileBackend::store_root_certificate(root, b"another"),
            Err(CaError::RootCertificateExists)
        ));
        assert_eq!(
            FileBackend::load_root_certificate(root).unwrap(),
            b"root der"
        );
        FileBackend::load(root, CaKind::Internal, &authority.identity).unwrap();
    }

    #[test]
    fn root_certificate_needs_an_initialized_authority_and_a_sane_size() {
        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            FileBackend::store_root_certificate(empty.path(), b"root der"),
            Err(CaError::NotInitialized(CaKind::Internal))
        ));
        assert!(matches!(
            FileBackend::load_root_certificate(empty.path()),
            Err(CaError::NotInitialized(CaKind::Internal))
        ));

        let authority = authority(CaKind::Internal);
        let root = authority.dir.path();
        for bad in [Vec::new(), vec![0u8; 16 * 1024 + 1]] {
            assert!(matches!(
                FileBackend::store_root_certificate(root, &bad),
                Err(CaError::InvalidRootCertificate { .. })
            ));
        }
        assert!(FileBackend::store_root_certificate(root, &vec![0u8; 16 * 1024]).is_ok());
    }

    #[test]
    fn foreign_identity_cannot_load() {
        let authority = authority(CaKind::User);
        let err = FileBackend::load(authority.dir.path(), CaKind::User, &AgeIdentity::generate())
            .unwrap_err();
        assert!(matches!(err, CaError::Decrypt));
        assert!(
            !err.to_string()
                .contains(&authority.dir.path().display().to_string())
        );
    }

    #[test]
    fn second_init_is_refused_and_changes_nothing() {
        let authority = authority(CaKind::User);
        let dir = authority.dir.path().join("user");
        let before = file_names(&dir);
        let active = fs::read(dir.join("active")).unwrap();
        let err = FileBackend::init(
            authority.dir.path(),
            CaKind::User,
            &authority.identity.recipient(),
        )
        .unwrap_err();
        assert!(matches!(err, CaError::AlreadyInitialized(CaKind::User)));
        assert_eq!(file_names(&dir), before);
        assert_eq!(fs::read(dir.join("active")).unwrap(), active);
        assert!(FileBackend::is_initialized(authority.dir.path(), CaKind::User).unwrap());
        assert!(!FileBackend::is_initialized(authority.dir.path(), CaKind::Host).unwrap());
    }

    #[test]
    fn load_of_missing_authority_fails() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            FileBackend::load(dir.path(), CaKind::Host, &AgeIdentity::generate()).unwrap_err();
        assert!(matches!(err, CaError::NotInitialized(CaKind::Host)));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private_to_the_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ca");
        let identity = AgeIdentity::generate();
        FileBackend::init(&root, CaKind::User, &identity.recipient()).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&root.join("user")), 0o700);
        for name in file_names(&root.join("user")) {
            assert_eq!(mode(&root.join("user").join(&name)), 0o600, "{name}");
        }
    }

    #[test]
    fn active_key_missing_from_the_set_or_malformed_is_rejected() {
        let authority = authority(CaKind::User);
        let active = authority.dir.path().join("user").join("active");

        fs::remove_file(&active).unwrap();
        fs::write(&active, format!("{}\n", "a".repeat(64))).unwrap();
        let err =
            FileBackend::load(authority.dir.path(), CaKind::User, &authority.identity).unwrap_err();
        assert!(matches!(err, CaError::ActiveKeyNotTrusted));

        for malformed in ["../../etc/passwd\n", "", &"A".repeat(64), &"a".repeat(65)] {
            fs::write(&active, malformed).unwrap();
            let err = FileBackend::load(authority.dir.path(), CaKind::User, &authority.identity)
                .unwrap_err();
            assert!(matches!(err, CaError::CorruptStore { .. }), "{malformed:?}");
        }
    }

    #[test]
    fn failure_after_linking_any_file_rolls_everything_back() {
        for target in ["active", ".age", ".pub"] {
            let dir = tempfile::tempdir().unwrap();
            let identity = AgeIdentity::generate();
            let fail_after_link = |path: &Path| {
                let name = path.file_name().unwrap().to_str().unwrap();
                if name.ends_with(target) {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            };

            let err = FileBackend::init_with(
                dir.path(),
                CaKind::User,
                &identity.recipient(),
                &fail_after_link,
            )
            .unwrap_err();
            assert!(matches!(err, CaError::Io { .. }), "{target}");
            assert!(file_names(&dir.path().join("user")).is_empty(), "{target}");
            assert!(!FileBackend::is_initialized(dir.path(), CaKind::User).unwrap());

            FileBackend::init(dir.path(), CaKind::User, &identity.recipient()).unwrap();
            assert!(FileBackend::load(dir.path(), CaKind::User, &identity).is_ok());
        }
    }

    #[test]
    fn public_key_files_must_match_their_names() {
        let authority = authority(CaKind::User);
        let dir = authority.dir.path().join("user");
        let active = fs::read_to_string(dir.join("active")).unwrap();
        let line = fs::read_to_string(dir.join(format!("{}.pub", active.trim()))).unwrap();

        fs::write(dir.join(format!("{}.pub", "a".repeat(64))), line).unwrap();
        let err =
            FileBackend::load(authority.dir.path(), CaKind::User, &authority.identity).unwrap_err();
        assert!(matches!(err, CaError::CorruptStore { .. }));
    }

    #[test]
    fn decrypted_key_must_match_the_active_fingerprint() {
        let first = authority(CaKind::User);
        let second_root = tempfile::tempdir().unwrap();
        FileBackend::init(
            second_root.path(),
            CaKind::User,
            &first.identity.recipient(),
        )
        .unwrap();

        let first_dir = first.dir.path().join("user");
        let second_dir = second_root.path().join("user");
        let first_name = file_names(&first_dir)
            .into_iter()
            .find(|name| name.ends_with(".age"))
            .unwrap();
        let second_name = file_names(&second_dir)
            .into_iter()
            .find(|name| name.ends_with(".age"))
            .unwrap();
        fs::copy(second_dir.join(second_name), first_dir.join(first_name)).unwrap();

        let err = FileBackend::load(first.dir.path(), CaKind::User, &first.identity).unwrap_err();
        assert!(matches!(err, CaError::CorruptStore { .. }));
    }

    #[test]
    fn trusted_keys_must_be_ed25519() {
        let authority = authority(CaKind::Host);
        let ed25519 = *authority.trust.active().key_data().ed25519().unwrap();
        let security_key = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")));
        let hex = fingerprint_hex(&security_key);
        let path = authority.dir.path().join("host").join(format!("{hex}.pub"));
        fs::write(&path, format!("{}\n", security_key.to_openssh().unwrap())).unwrap();

        let err =
            FileBackend::load(authority.dir.path(), CaKind::Host, &authority.identity).unwrap_err();
        assert!(matches!(err, CaError::UnsupportedKeyAlgorithm));
    }

    #[test]
    fn debug_output_reveals_only_the_fingerprint() {
        let authority = authority(CaKind::User);
        let keypair = authority.backend.private_key.key_data().ed25519().unwrap();
        let secret = keypair.private.to_bytes();
        let pem = authority
            .backend
            .private_key
            .to_openssh(LineEnding::LF)
            .unwrap();
        let printed = format!("{:?} {:#?}", authority.backend, authority.backend);

        assert!(printed.contains("FileBackend"));
        assert!(
            printed.contains(
                &authority
                    .backend
                    .public_key()
                    .fingerprint(HashAlg::Sha256)
                    .to_string()
            )
        );
        let lower: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!printed.to_lowercase().contains(&lower));
        assert!(!printed.contains(&format!("{secret:?}")));
        assert!(!printed.contains("PRIVATE KEY"));
        assert!(!printed.to_uppercase().contains("AGE-SECRET-KEY"));
        for body_line in pem.lines().filter(|line| line.len() > 20) {
            assert!(!printed.contains(body_line));
        }
    }
}
