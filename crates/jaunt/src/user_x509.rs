use std::fmt;
use std::fs::{self, DirBuilder, File};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{X509CertificateRequest, X509CertificateResponse};
use rustix::fs::{Mode, OFlags, open};
use rustix::io::Errno;
use rustix::process::geteuid;
use ssh_key::Certificate;
use ssh_key::private::Ed25519Keypair;
use ssh_key::rand_core::{OsRng, RngCore};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use zeroize::Zeroizing;

use crate::client::{ApiClient, ApiError};
use crate::ensure::MIN_REMAINING_SECS;
use crate::lock::ProfileLock;
use crate::secret::Secret;
use crate::status::Session;
use crate::store::{
    ProfileStore, SIBLING_COUNTER, StoreError, X509_CERT_FILE, X509_KEY_FILE, shred, sync_dir,
    write_new_file,
};

const SEED_LEN: usize = 32;
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const DIR_MODE: u32 = 0o700;
const GROUP_OR_OTHER: u32 = 0o077;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_CERTIFICATE_DER_BYTES: usize = 16 * 1024;
const MAX_CERTIFICATE_TEXT_LEN: usize = MAX_CERTIFICATE_DER_BYTES.div_ceil(3) * 4;
const USER_URN_PREFIX: &str = "urn:jaunt:user:";
const KEY_LABEL: &str = "PRIVATE KEY";
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const PEM_LINE_LEN: usize = 64;
const UUID_GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IssuedError {
    #[error("it cannot be read")]
    Unreadable,
    #[error("it is for a different key")]
    WrongKey,
    #[error("it does not name exactly this user")]
    WrongIdentity,
    #[error("it may be used for more than client authentication")]
    WrongUsage,
    #[error("it is a CA certificate")]
    IsCa,
    #[error("it is not valid at this time")]
    OutsideValidity,
    #[error("its end differs from the one the server reported")]
    Inconsistent,
    #[error("it outlives the SSH certificate")]
    OutlivesSession,
}

#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    #[error("no sign-in was found in {dir}: run `jaunt login`")]
    NotSignedIn { dir: PathBuf },
    #[error("the sign-in expires within a minute: run `jaunt login`")]
    SignInExpiring,
    #[error("the held lock belongs to another profile")]
    ForeignLock,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is not a regular file")]
    NotARegularFile { path: PathBuf },
    #[error("{path} is not a plain directory")]
    NotADirectory { path: PathBuf },
    #[error("{path} belongs to another user; remove it and try again")]
    ForeignOwner { path: PathBuf },
    #[error("{path} can be read by other users; restrict it with `chmod 600 {path}`")]
    ExposedFile { path: PathBuf },
    #[error("{path} can be used by other users; restrict it with `chmod 700 {path}`")]
    ExposedDirectory { path: PathBuf },
    #[error("{path} is too large")]
    TooLarge { path: PathBuf },
    #[error("{path} is not an Ed25519 key written by jaunt; remove it to have a new key made")]
    CorruptKey { path: PathBuf },
    #[error("{path} is missing or does not match the key: run `jaunt login` again")]
    UnusableCertificate { path: PathBuf },
    #[error("cannot generate a key: the system entropy source failed")]
    Entropy,
    #[error("this server does not issue X.509 certificates")]
    NotOffered,
    #[error(transparent)]
    Api(ApiError),
    #[error("the X.509 certificate from the server was refused: {0}")]
    Refused(#[from] IssuedError),
    #[error("{path} cannot be used: it is damaged or does not belong to the stored key")]
    DamagedCertificate { path: PathBuf },
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> X509Error {
    X509Error::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCertificate {
    pub key_path: PathBuf,
    pub certificate_path: PathBuf,
    pub valid_before: i64,
}

pub trait CertificateIssuer {
    fn issue(&self, public_key: &str) -> Result<X509CertificateResponse, ApiError>;
}

pub struct ServerIssuer {
    client: ApiClient,
    token: Secret,
}

impl ServerIssuer {
    pub fn for_profile(store: &ProfileStore) -> Result<ServerIssuer, X509Error> {
        let not_signed_in = || X509Error::NotSignedIn {
            dir: store.dir().to_owned(),
        };
        let server = store.read_server()?.ok_or_else(not_signed_in)?;
        let token = store.read_token()?.ok_or_else(not_signed_in)?;
        let client = ApiClient::new(&server).map_err(X509Error::Api)?;
        Ok(ServerIssuer { client, token })
    }
}

impl CertificateIssuer for ServerIssuer {
    fn issue(&self, public_key: &str) -> Result<X509CertificateResponse, ApiError> {
        self.client.issue_x509(
            &self.token,
            &X509CertificateRequest {
                public_key: public_key.to_owned(),
            },
        )
    }
}

pub struct UserKey {
    pkcs8: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

impl UserKey {
    fn generate() -> Result<UserKey, X509Error> {
        let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| X509Error::Entropy)?;
        Ok(UserKey::from_seed(&seed))
    }

    fn from_pkcs8(der: &[u8]) -> Option<UserKey> {
        let seed = der
            .strip_prefix(ED25519_PKCS8_PREFIX.as_slice())
            .and_then(|rest| <[u8; SEED_LEN]>::try_from(rest).ok())
            .map(Zeroizing::new)?;
        Some(UserKey::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; SEED_LEN]) -> UserKey {
        let keypair = Ed25519Keypair::from_seed(seed);
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + SEED_LEN));
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(seed);
        let spki = [ED25519_SPKI_PREFIX.as_slice(), keypair.public.0.as_slice()].concat();
        UserKey { pkcs8, spki }
    }

    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    fn pem(&self) -> Zeroizing<String> {
        pem_encode(KEY_LABEL, &self.pkcs8)
    }
}

impl fmt::Debug for UserKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserKey")
            .field("private", &"[redacted]")
            .finish()
    }
}

pub struct Expected<'a> {
    pub spki: &'a [u8],
    pub user_id: &'a str,
    pub ssh_valid_before: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub der: Vec<u8>,
    pub valid_before: i64,
}

pub struct X509Identity {
    certificate_der: Vec<u8>,
    key_pkcs8: Zeroizing<Vec<u8>>,
}

impl X509Identity {
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn key_pkcs8(&self) -> &[u8] {
        &self.key_pkcs8
    }
}

impl fmt::Debug for X509Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X509Identity")
            .field("certificate_bytes", &self.certificate_der.len())
            .field("key", &"[redacted]")
            .finish()
    }
}

pub fn load_identity(
    store: &ProfileStore,
    lock: &ProfileLock,
    certificate: &UserCertificate,
) -> Result<X509Identity, X509Error> {
    if lock.path() != store.lock_path() {
        return Err(X509Error::ForeignLock);
    }
    let key = load_key(&certificate.key_path)?.ok_or_else(|| X509Error::CorruptKey {
        path: certificate.key_path.clone(),
    })?;
    let unusable = || X509Error::UnusableCertificate {
        path: certificate.certificate_path.clone(),
    };
    let pem = read_file(&certificate.certificate_path, Secrecy::Public)?.ok_or_else(unusable)?;
    let der = pem_decode(CERTIFICATE_LABEL, &pem).ok_or_else(unusable)?;
    let (rest, parsed) = X509Certificate::from_der(&der).map_err(|_| unusable())?;
    if !rest.is_empty() || parsed.public_key().raw != key.spki_der() {
        return Err(unusable());
    }
    Ok(X509Identity {
        certificate_der: der.to_vec(),
        key_pkcs8: key.pkcs8.clone(),
    })
}

pub fn ensure_x509(
    store: &ProfileStore,
    lock: &ProfileLock,
    now: i64,
) -> Result<UserCertificate, X509Error> {
    let issuer = ServerIssuer::for_profile(store)?;
    ensure_x509_with(store, lock, &issuer, now)
}

pub fn ensure_x509_with(
    store: &ProfileStore,
    lock: &ProfileLock,
    issuer: &dyn CertificateIssuer,
    now: i64,
) -> Result<UserCertificate, X509Error> {
    if lock.path() != store.lock_path() {
        return Err(X509Error::ForeignLock);
    }
    let not_signed_in = || X509Error::NotSignedIn {
        dir: store.dir().to_owned(),
    };
    let session = Session::load(store)?.ok_or_else(not_signed_in)?;
    let ssh_valid_before = ssh_valid_before(store)?.ok_or_else(not_signed_in)?;
    if ssh_valid_before.saturating_sub(now) < MIN_REMAINING_SECS {
        return Err(X509Error::SignInExpiring);
    }
    let dir = store.x509_dir();
    prepare_dir(&dir)?;
    let key = load_or_create_key(&dir)?;
    let key_path = dir.join(X509_KEY_FILE);
    let certificate_path = dir.join(X509_CERT_FILE);
    if let Some(stored) = read_file(&certificate_path, Secrecy::Public)?
        && let Some(valid_before) = reusable(&stored, &key, &session.meta.user_id, now)
    {
        return Ok(UserCertificate {
            key_path,
            certificate_path,
            valid_before,
        });
    }
    let response = issuer
        .issue(&STANDARD.encode(key.spki_der()))
        .map_err(|err| match err {
            ApiError::NotConfigured | ApiError::Rejected { status: 404 } => X509Error::NotOffered,
            other => X509Error::Api(other),
        })?;
    let issued = check_issued(
        &response,
        &Expected {
            spki: key.spki_der(),
            user_id: &session.meta.user_id,
            ssh_valid_before,
            now,
        },
    )?;
    store_certificate(&dir, &certificate_path, &issued.der)?;
    Ok(UserCertificate {
        key_path,
        certificate_path,
        valid_before: issued.valid_before,
    })
}

pub fn check_issued(
    response: &X509CertificateResponse,
    expected: &Expected<'_>,
) -> Result<IssuedCertificate, IssuedError> {
    if response.certificate_der.len() > MAX_CERTIFICATE_TEXT_LEN {
        return Err(IssuedError::Unreadable);
    }
    let der = STANDARD
        .decode(&response.certificate_der)
        .ok()
        .filter(|der| !der.is_empty() && der.len() <= MAX_CERTIFICATE_DER_BYTES)
        .ok_or(IssuedError::Unreadable)?;
    let (rest, certificate) =
        X509Certificate::from_der(&der).map_err(|_| IssuedError::Unreadable)?;
    if !rest.is_empty() {
        return Err(IssuedError::Unreadable);
    }
    if certificate.public_key().raw != expected.spki {
        return Err(IssuedError::WrongKey);
    }
    if !names_only_user(&certificate, expected.user_id) {
        return Err(IssuedError::WrongIdentity);
    }
    if !client_auth_only(&certificate) {
        return Err(IssuedError::WrongUsage);
    }
    let is_ca = certificate
        .basic_constraints()
        .map_err(|_| IssuedError::Unreadable)?
        .is_some_and(|constraints| constraints.value.ca);
    if is_ca {
        return Err(IssuedError::IsCa);
    }
    let validity = certificate.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    if expected.now < not_before || expected.now >= not_after {
        return Err(IssuedError::OutsideValidity);
    }
    if not_after != response.valid_before {
        return Err(IssuedError::Inconsistent);
    }
    if not_after > expected.ssh_valid_before {
        return Err(IssuedError::OutlivesSession);
    }
    Ok(IssuedCertificate {
        der,
        valid_before: not_after,
    })
}

fn reusable(pem: &[u8], key: &UserKey, user_id: &str, now: i64) -> Option<i64> {
    let der = pem_decode(CERTIFICATE_LABEL, pem)?;
    let (rest, certificate) = X509Certificate::from_der(&der).ok()?;
    let not_after = certificate.validity().not_after.timestamp();
    let fresh = rest.is_empty()
        && certificate.public_key().raw == key.spki_der()
        && names_only_user(&certificate, user_id)
        && certificate.validity().not_before.timestamp() <= now
        && not_after.saturating_sub(now) >= MIN_REMAINING_SECS;
    fresh.then_some(not_after)
}

fn names_only_user(certificate: &X509Certificate<'_>, user_id: &str) -> bool {
    if !is_canonical_uuid(user_id) {
        return false;
    }
    let expected = format!("{USER_URN_PREFIX}{user_id}");
    match certificate.subject_alternative_name() {
        Ok(Some(names)) => matches!(
            names.value.general_names.as_slice(),
            [GeneralName::URI(uri)] if *uri == expected
        ),
        _ => false,
    }
}

fn client_auth_only(certificate: &X509Certificate<'_>) -> bool {
    match certificate.extended_key_usage() {
        Ok(Some(usage)) => {
            let usage = usage.value;
            usage.client_auth
                && !usage.any
                && !usage.server_auth
                && !usage.code_signing
                && !usage.email_protection
                && !usage.time_stamping
                && !usage.ocsp_signing
                && usage.other.is_empty()
        }
        _ => false,
    }
}

fn is_canonical_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == UUID_GROUPS.len()
        && groups.iter().zip(UUID_GROUPS).all(|(group, len)| {
            group.len() == len
                && group
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn ssh_valid_before(store: &ProfileStore) -> Result<Option<i64>, X509Error> {
    let Some(line) = store.read_certificate_line()? else {
        return Ok(None);
    };
    Ok(Certificate::from_openssh(&line)
        .ok()
        .map(|certificate| i64::try_from(certificate.valid_before()).unwrap_or(i64::MAX)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Secrecy {
    Secret,
    Public,
}

fn read_file(path: &Path, secrecy: Secrecy) -> Result<Option<Zeroizing<Vec<u8>>>, X509Error> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP | Errno::MLINK) => {
            return Err(X509Error::NotARegularFile {
                path: path.to_owned(),
            });
        }
        Err(errno) => return Err(io_error("open", path, errno.into())),
    };
    let meta = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    refuse_unsafe(
        path,
        &FileFacts {
            regular: meta.is_file(),
            owner: meta.uid(),
            mode: meta.mode(),
            len: meta.len(),
        },
        geteuid().as_raw(),
        secrecy,
    )?;
    let capacity = usize::try_from(meta.len()).unwrap_or(0).saturating_add(1);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("read", path, err))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(X509Error::TooLarge {
            path: path.to_owned(),
        });
    }
    Ok(Some(bytes))
}

struct FileFacts {
    regular: bool,
    owner: u32,
    mode: u32,
    len: u64,
}

fn refuse_unsafe(
    path: &Path,
    facts: &FileFacts,
    euid: u32,
    secrecy: Secrecy,
) -> Result<(), X509Error> {
    let path = path.to_owned();
    if !facts.regular {
        return Err(X509Error::NotARegularFile { path });
    }
    if facts.owner != euid {
        return Err(X509Error::ForeignOwner { path });
    }
    if secrecy == Secrecy::Secret && facts.mode & GROUP_OR_OTHER != 0 {
        return Err(X509Error::ExposedFile { path });
    }
    if facts.len > MAX_FILE_BYTES {
        return Err(X509Error::TooLarge { path });
    }
    Ok(())
}

fn prepare_dir(dir: &Path) -> Result<(), X509Error> {
    match DirBuilder::new().mode(DIR_MODE).create(dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_error("create", dir, err)),
    }
    let meta = fs::symlink_metadata(dir).map_err(|err| io_error("inspect", dir, err))?;
    if !meta.is_dir() {
        return Err(X509Error::NotADirectory {
            path: dir.to_owned(),
        });
    }
    if meta.uid() != geteuid().as_raw() {
        return Err(X509Error::ForeignOwner {
            path: dir.to_owned(),
        });
    }
    if meta.mode() & GROUP_OR_OTHER != 0 {
        return Err(X509Error::ExposedDirectory {
            path: dir.to_owned(),
        });
    }
    Ok(())
}

fn load_or_create_key(dir: &Path) -> Result<UserKey, X509Error> {
    if let Some(key) = load_key(&dir.join(X509_KEY_FILE))? {
        return Ok(key);
    }
    install_key(dir, UserKey::generate()?)
}

fn install_key(dir: &Path, key: UserKey) -> Result<UserKey, X509Error> {
    let path = dir.join(X509_KEY_FILE);
    let temporary = temporary_path(dir, X509_KEY_FILE);
    if let Err(err) = write_new_file(&temporary, key.pem().as_bytes()) {
        drop(shred(&temporary));
        return Err(io_error("write", &temporary, err));
    }
    match fs::hard_link(&temporary, &path) {
        Ok(()) => {
            fs::remove_file(&temporary).map_err(|err| io_error("remove", &temporary, err))?;
            sync_dir(dir)?;
            Ok(key)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            shred(&temporary)?;
            load_key(&path)?.ok_or(X509Error::CorruptKey { path })
        }
        Err(err) => {
            drop(shred(&temporary));
            Err(io_error("install", &path, err))
        }
    }
}

fn load_key(path: &Path) -> Result<Option<UserKey>, X509Error> {
    let Some(bytes) = read_file(path, Secrecy::Secret)? else {
        return Ok(None);
    };
    pem_decode(KEY_LABEL, &bytes)
        .and_then(|der| UserKey::from_pkcs8(&der))
        .map(Some)
        .ok_or_else(|| X509Error::CorruptKey {
            path: path.to_owned(),
        })
}

fn store_certificate(dir: &Path, path: &Path, der: &[u8]) -> Result<(), X509Error> {
    let temporary = temporary_path(dir, X509_CERT_FILE);
    let pem = pem_encode(CERTIFICATE_LABEL, der);
    if let Err(err) = write_new_file(&temporary, pem.as_bytes()) {
        drop(fs::remove_file(&temporary));
        return Err(io_error("write", &temporary, err));
    }
    if let Err(err) = fs::rename(&temporary, path) {
        drop(fs::remove_file(&temporary));
        return Err(io_error("replace", path, err));
    }
    sync_dir(dir)?;
    Ok(())
}

fn temporary_path(dir: &Path, name: &str) -> PathBuf {
    let serial = SIBLING_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(".{name}.{}.{serial}.tmp", std::process::id()))
}

pub struct UserIdentity {
    certificate_pem: String,
    key_pem: Zeroizing<String>,
    pub valid_before: i64,
}

impl UserIdentity {
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }
}

impl fmt::Debug for UserIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserIdentity")
            .field("valid_before", &self.valid_before)
            .field("key", &"[redacted]")
            .finish_non_exhaustive()
    }
}

pub fn read_identity(issued: &UserCertificate) -> Result<UserIdentity, X509Error> {
    let missing = |path: &Path| io_error("read", path, io::ErrorKind::NotFound.into());
    let key = load_key(&issued.key_path)?.ok_or_else(|| missing(&issued.key_path))?;
    let damaged = || X509Error::DamagedCertificate {
        path: issued.certificate_path.clone(),
    };
    let stored = read_file(&issued.certificate_path, Secrecy::Public)?
        .ok_or_else(|| missing(&issued.certificate_path))?;
    let der = pem_decode(CERTIFICATE_LABEL, &stored).ok_or_else(damaged)?;
    let (rest, certificate) = X509Certificate::from_der(&der).map_err(|_| damaged())?;
    if !rest.is_empty() || certificate.public_key().raw != key.spki_der() {
        return Err(damaged());
    }
    Ok(UserIdentity {
        certificate_pem: pem_encode(CERTIFICATE_LABEL, &der).as_str().to_owned(),
        key_pem: key.pem(),
        valid_before: certificate.validity().not_after.timestamp(),
    })
}

pub(crate) fn pem_encode(label: &str, der: &[u8]) -> Zeroizing<String> {
    let body = Zeroizing::new(STANDARD.encode(der));
    let mut text = Zeroizing::new(String::with_capacity(body.len() * 2 + 2 * label.len() + 64));
    text.push_str("-----BEGIN ");
    text.push_str(label);
    text.push_str("-----\n");
    for line in body.as_bytes().chunks(PEM_LINE_LEN) {
        text.extend(line.iter().copied().map(char::from));
        text.push('\n');
    }
    text.push_str("-----END ");
    text.push_str(label);
    text.push_str("-----\n");
    text
}

fn pem_decode(label: &str, pem: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let text = std::str::from_utf8(pem).ok()?;
    let body = text
        .strip_prefix("-----BEGIN ")?
        .strip_prefix(label)?
        .strip_prefix("-----\n")?
        .strip_suffix("-----\n")?
        .strip_suffix(label)?
        .strip_suffix("-----END ")?;
    let mut joined = Zeroizing::new(String::with_capacity(body.len()));
    for line in body.lines() {
        if line.len() > PEM_LINE_LEN {
            return None;
        }
        joined.push_str(line);
    }
    STANDARD.decode(joined.as_bytes()).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_proto::X509CertificateResponse;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, PKCS_ED25519, SanType, SubjectPublicKeyInfo,
    };
    use rustix::process::geteuid;
    use ssh_key::certificate::{Builder, CertType};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};
    use tempfile::TempDir;

    use super::{
        CertificateIssuer, FileFacts, IssuedError, Secrecy, X509Error, ensure_x509_with,
        refuse_unsafe,
    };
    use crate::client::ApiError;
    use crate::lock::ProfileLock;
    use crate::profile::ProfileName;
    use crate::store::{ProfileMeta, ProfileStore};

    const NOW: i64 = 1_800_000_000;
    const SSH_END: i64 = NOW + 3600;
    const USER_ID: &str = "3f2b1c9e-7a44-4d0e-9c58-0a6b8f1d2e77";

    struct Fixture {
        _root: TempDir,
        store: ProfileStore,
        lock: ProfileLock,
    }

    impl Fixture {
        fn new(ssh_end: i64) -> Fixture {
            let root = tempfile::tempdir().unwrap();
            let home = root.path().join("state");
            let store = ProfileStore::new(&home, &ProfileName::default_name());
            fs::create_dir_all(store.dir()).unwrap();
            fs::write(store.dir().join("server"), "https://jaunt.example.com\n").unwrap();
            fs::write(store.dir().join("token"), "jt_token").unwrap();
            let meta = ProfileMeta {
                user_id: USER_ID.to_owned(),
                email: "alice@example.com".to_owned(),
                serial: 7,
                key_id: "jaunt:alice@example.com:7".to_owned(),
                valid_after: NOW - 100,
                valid_before: ssh_end,
                token_expires_at: ssh_end,
                host_ca_keys: Vec::new(),
            };
            fs::write(
                store.dir().join("meta.json"),
                serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
            let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let subject = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
            let mut builder = Builder::new_with_random_nonce(
                &mut OsRng,
                subject.public_key().key_data().clone(),
                u64::try_from(NOW - 100).unwrap(),
                u64::try_from(ssh_end).unwrap(),
            )
            .unwrap();
            builder.cert_type(CertType::User).unwrap();
            builder.valid_principal(USER_ID).unwrap();
            let line = builder.sign(&ca).unwrap().to_openssh().unwrap();
            fs::write(store.dir().join("id_ed25519-cert.pub"), line).unwrap();
            let lock = ProfileLock::acquire(
                &home,
                &store.lock_path(),
                Instant::now() + Duration::from_secs(5),
                &mut || {},
            )
            .unwrap();
            Fixture {
                _root: root,
                store,
                lock,
            }
        }

        fn ensure(&self, issuer: &Scripted) -> Result<super::UserCertificate, X509Error> {
            ensure_x509_with(&self.store, &self.lock, issuer, NOW)
        }

        fn key_path(&self) -> PathBuf {
            self.store.x509_dir().join("key.pem")
        }

        fn cert_path(&self) -> PathBuf {
            self.store.x509_dir().join("cert.pem")
        }

        fn set_user(&self, user_id: &str) {
            let path = self.store.dir().join("meta.json");
            let mut meta: ProfileMeta = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            meta.user_id = user_id.to_owned();
            fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
        }

        fn spki(&self) -> Vec<u8> {
            super::load_key(&self.key_path())
                .unwrap()
                .unwrap()
                .spki_der()
                .to_vec()
        }

        fn plant(&self, shape: &Shape) {
            let response = certificate(&self.spki(), shape);
            let der = STANDARD.decode(response.certificate_der).unwrap();
            fs::write(
                self.cert_path(),
                super::pem_encode("CERTIFICATE", &der).as_bytes(),
            )
            .unwrap();
        }
    }

    #[derive(Clone)]
    struct Shape {
        other_key: bool,
        names: Vec<String>,
        usages: Vec<ExtendedKeyUsagePurpose>,
        ca: bool,
        not_before: i64,
        not_after: i64,
        reported_end: Option<i64>,
    }

    impl Shape {
        fn honest(not_after: i64) -> Shape {
            Shape {
                other_key: false,
                names: vec![format!("urn:jaunt:user:{USER_ID}")],
                usages: vec![ExtendedKeyUsagePurpose::ClientAuth],
                ca: false,
                not_before: NOW - 60,
                not_after,
                reported_end: None,
            }
        }
    }

    fn certificate(spki: &[u8], shape: &Shape) -> X509CertificateResponse {
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = CertifiedIssuer::self_signed(root, KeyPair::generate().unwrap()).unwrap();
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = shape
            .names
            .iter()
            .map(|name| match name.strip_prefix("dns:") {
                Some(dns) => SanType::DnsName(dns.try_into().unwrap()),
                None => SanType::URI(name.as_str().try_into().unwrap()),
            })
            .collect();
        params.extended_key_usages.clone_from(&shape.usages);
        params.is_ca = if shape.ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params.not_before = epoch + Duration::from_secs(u64::try_from(shape.not_before).unwrap());
        params.not_after = epoch + Duration::from_secs(u64::try_from(shape.not_after).unwrap());
        let issued = if shape.other_key {
            let other = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            params.signed_by(&other, &issuer).unwrap()
        } else {
            let subject = SubjectPublicKeyInfo::from_der(spki).unwrap();
            params.signed_by(&subject, &issuer).unwrap()
        };
        X509CertificateResponse {
            certificate_der: STANDARD.encode(issued.der()),
            serial: 9,
            parent_serial: 7,
            valid_after: shape.not_before,
            valid_before: shape.reported_end.unwrap_or(shape.not_after),
        }
    }

    type Reply = dyn Fn(&[u8]) -> Result<X509CertificateResponse, ApiError>;

    struct Scripted {
        calls: Cell<usize>,
        reply: Box<Reply>,
    }

    impl Scripted {
        fn new(
            reply: impl Fn(&[u8]) -> Result<X509CertificateResponse, ApiError> + 'static,
        ) -> Scripted {
            Scripted {
                calls: Cell::new(0),
                reply: Box::new(reply),
            }
        }

        fn shaped(shape: Shape) -> Scripted {
            Scripted::new(move |spki| Ok(certificate(spki, &shape)))
        }
    }

    impl CertificateIssuer for Scripted {
        fn issue(&self, public_key: &str) -> Result<X509CertificateResponse, ApiError> {
            self.calls.set(self.calls.get() + 1);
            (self.reply)(&STANDARD.decode(public_key).unwrap())
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_loaded_identity_needs_this_profile_lock_and_a_certificate_for_the_stored_key() {
        let fixture = Fixture::new(SSH_END);
        let issued = fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();

        let identity = super::load_identity(&fixture.store, &fixture.lock, &issued).unwrap();

        assert!(!identity.certificate_der().is_empty());
        assert_eq!(identity.key_pkcs8().len(), 48);
        assert!(format!("{identity:?}").contains("[redacted]"));
        let home = fixture.store.home();
        let other = ProfileLock::acquire(
            home,
            &home.join(".other.lock"),
            Instant::now() + Duration::from_secs(5),
            &mut || {},
        )
        .unwrap();
        assert!(matches!(
            super::load_identity(&fixture.store, &other, &issued),
            Err(X509Error::ForeignLock)
        ));
        fs::remove_file(fixture.key_path()).unwrap();
        super::install_key(
            &fixture.store.x509_dir(),
            super::UserKey::generate().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            super::load_identity(&fixture.store, &fixture.lock, &issued),
            Err(X509Error::UnusableCertificate { .. })
        ));
    }

    #[test]
    fn the_key_is_made_once_with_private_modes_and_a_fresh_certificate_is_reused() {
        let fixture = Fixture::new(SSH_END);
        let issuer = Scripted::shaped(Shape::honest(SSH_END));

        let first = fixture.ensure(&issuer).unwrap();
        let key = fs::read(fixture.key_path()).unwrap();
        let second = fixture.ensure(&issuer).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.valid_before, SSH_END);
        assert_eq!(issuer.calls.get(), 1);
        assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
        assert!(key.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
        assert_eq!(mode(&fixture.store.x509_dir()), 0o700);
        assert_eq!(mode(&fixture.key_path()), 0o600);
        assert_eq!(mode(&fixture.cert_path()), 0o600);
        assert_eq!(first.key_path, fixture.key_path());
        assert_eq!(first.certificate_path, fixture.cert_path());
    }

    #[test]
    fn a_certificate_near_its_end_or_for_another_key_is_replaced_but_the_key_is_kept() {
        for (lifetime, reissued) in [(60, false), (59, true)] {
            let fixture = Fixture::new(SSH_END);
            fixture
                .ensure(&Scripted::shaped(Shape::honest(NOW + lifetime)))
                .unwrap();
            let key = fs::read(fixture.key_path()).unwrap();
            let issuer = Scripted::shaped(Shape::honest(SSH_END));

            let renewed = fixture.ensure(&issuer).unwrap();

            assert_eq!(issuer.calls.get(), usize::from(reissued), "{lifetime}");
            let expected = if reissued { SSH_END } else { NOW + lifetime };
            assert_eq!(renewed.valid_before, expected, "{lifetime}");
            assert_eq!(fs::read(fixture.key_path()).unwrap(), key);
        }

        let fixture = Fixture::new(SSH_END);
        let mut foreign = Shape::honest(SSH_END);
        foreign.other_key = true;
        let stray = certificate(&[], &foreign);
        fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();
        let der = STANDARD.decode(stray.certificate_der).unwrap();
        fs::write(
            fixture.cert_path(),
            super::pem_encode("CERTIFICATE", &der).as_bytes(),
        )
        .unwrap();
        let issuer = Scripted::shaped(Shape::honest(SSH_END));

        fixture.ensure(&issuer).unwrap();

        assert_eq!(issuer.calls.get(), 1);
        assert_ne!(
            fs::read(fixture.cert_path()).unwrap(),
            super::pem_encode("CERTIFICATE", &der).as_bytes()
        );
    }

    #[test]
    fn a_stored_certificate_for_another_user_or_not_yet_valid_is_replaced() {
        let fixture = Fixture::new(SSH_END);
        fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();
        let other_user = "00000000-0000-0000-0000-00000000000b";
        fixture.set_user(other_user);
        let mut for_other = Shape::honest(SSH_END);
        for_other.names = vec![format!("urn:jaunt:user:{other_user}")];
        let issuer = Scripted::shaped(for_other);

        fixture.ensure(&issuer).unwrap();

        assert_eq!(issuer.calls.get(), 1);
        let again = Scripted::shaped(Shape::honest(SSH_END));
        fixture.ensure(&again).unwrap();
        assert_eq!(again.calls.get(), 0);

        let fixture = Fixture::new(SSH_END);
        fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();
        let mut future = Shape::honest(SSH_END);
        future.not_before = NOW + 1;
        fixture.plant(&future);
        let issuer = Scripted::shaped(Shape::honest(SSH_END));

        fixture.ensure(&issuer).unwrap();

        assert_eq!(issuer.calls.get(), 1);
    }

    #[test]
    fn any_usage_besides_client_authentication_is_refused() {
        let extras = [
            ExtendedKeyUsagePurpose::Any,
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::CodeSigning,
            ExtendedKeyUsagePurpose::EmailProtection,
            ExtendedKeyUsagePurpose::TimeStamping,
            ExtendedKeyUsagePurpose::OcspSigning,
            ExtendedKeyUsagePurpose::Other(vec![1, 3, 6, 1, 4, 1, 99999, 1]),
        ];
        for extra in extras {
            let fixture = Fixture::new(SSH_END);
            let mut shape = Shape::honest(SSH_END);
            shape.usages.push(extra.clone());

            let outcome = fixture.ensure(&Scripted::shaped(shape));

            assert!(
                matches!(outcome, Err(X509Error::Refused(IssuedError::WrongUsage))),
                "{extra:?}: {outcome:?}"
            );
            assert!(!fixture.cert_path().exists());
        }
    }

    #[test]
    fn the_ssh_certificate_must_have_a_full_minute_left() {
        for (left, allowed) in [(60, true), (59, false)] {
            let fixture = Fixture::new(NOW + left);
            let issuer = Scripted::shaped(Shape::honest(NOW + left));

            let outcome = fixture.ensure(&issuer);

            assert_eq!(outcome.is_ok(), allowed, "{left}: {outcome:?}");
            if !allowed {
                assert!(matches!(outcome, Err(X509Error::SignInExpiring)));
                assert_eq!(issuer.calls.get(), 0);
            }
        }
    }

    #[test]
    fn a_key_that_appears_before_the_install_is_kept() {
        let fixture = Fixture::new(SSH_END);
        let dir = fixture.store.x509_dir();
        super::prepare_dir(&dir).unwrap();
        let first = super::install_key(&dir, super::UserKey::generate().unwrap()).unwrap();
        let written = fs::read(fixture.key_path()).unwrap();

        let second = super::install_key(&dir, super::UserKey::generate().unwrap()).unwrap();

        assert_eq!(second.spki_der(), first.spki_der());
        assert_eq!(fs::read(fixture.key_path()).unwrap(), written);
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "a temporary file was left"
        );
    }

    #[test]
    fn each_lying_answer_is_refused_and_nothing_is_stored() {
        let honest = Shape::honest(SSH_END);
        let change = |edit: &dyn Fn(&mut Shape)| {
            let mut shape = honest.clone();
            edit(&mut shape);
            shape
        };
        let cases = [
            (change(&|s| s.other_key = true), IssuedError::WrongKey),
            (
                change(&|s| s.names.push("dns:web.example.test".to_owned())),
                IssuedError::WrongIdentity,
            ),
            (
                change(&|s| s.names = vec![format!("urn:jaunt:node:{USER_ID}")]),
                IssuedError::WrongIdentity,
            ),
            (
                change(&|s| {
                    s.names = vec!["urn:jaunt:user:00000000-0000-0000-0000-000000000001".to_owned()]
                }),
                IssuedError::WrongIdentity,
            ),
            (change(&|s| s.names.clear()), IssuedError::WrongIdentity),
            (change(&|s| s.ca = true), IssuedError::IsCa),
            (
                change(&|s| s.usages.push(ExtendedKeyUsagePurpose::ServerAuth)),
                IssuedError::WrongUsage,
            ),
            (change(&|s| s.usages.clear()), IssuedError::WrongUsage),
            (
                change(&|s| {
                    s.not_before = NOW - 200;
                    s.not_after = NOW - 100;
                }),
                IssuedError::OutsideValidity,
            ),
            (
                change(&|s| s.not_before = NOW + 1),
                IssuedError::OutsideValidity,
            ),
            (
                change(&|s| s.not_after = SSH_END + 1),
                IssuedError::OutlivesSession,
            ),
            (
                change(&|s| s.reported_end = Some(SSH_END - 1)),
                IssuedError::Inconsistent,
            ),
        ];
        for (shape, expected) in cases {
            let fixture = Fixture::new(SSH_END);

            let outcome = fixture.ensure(&Scripted::shaped(shape));

            assert!(
                matches!(outcome, Err(X509Error::Refused(found)) if found == expected),
                "{expected:?}: {outcome:?}"
            );
            assert!(!fixture.cert_path().exists(), "{expected:?}");
        }
        let fixture = Fixture::new(SSH_END);
        let trailing = Scripted::new(move |spki| {
            let mut response = certificate(spki, &honest);
            let mut der = STANDARD.decode(&response.certificate_der).unwrap();
            der.push(0);
            response.certificate_der = STANDARD.encode(der);
            Ok(response)
        });
        let outcome = fixture.ensure(&trailing);
        assert!(
            matches!(outcome, Err(X509Error::Refused(IssuedError::Unreadable))),
            "{outcome:?}"
        );
        assert!(!fixture.cert_path().exists());
        for garbage in ["not base64!", "bm90IGEgY2VydGlmaWNhdGU=", ""] {
            let fixture = Fixture::new(SSH_END);
            let issuer = Scripted::new(move |_| {
                Ok(X509CertificateResponse {
                    certificate_der: garbage.to_owned(),
                    serial: 9,
                    parent_serial: 7,
                    valid_after: NOW,
                    valid_before: SSH_END,
                })
            });

            let outcome = fixture.ensure(&issuer);

            assert!(
                matches!(outcome, Err(X509Error::Refused(IssuedError::Unreadable))),
                "{garbage:?}: {outcome:?}"
            );
            assert!(!fixture.cert_path().exists());
        }
    }

    #[test]
    fn the_key_file_must_be_a_private_regular_file_of_this_user() {
        let fixture = Fixture::new(SSH_END);
        fs::create_dir(fixture.store.x509_dir()).unwrap();
        fs::set_permissions(fixture.store.x509_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        let elsewhere = fixture.store.home().join("elsewhere.pem");
        fs::write(&elsewhere, "target").unwrap();
        symlink(&elsewhere, fixture.key_path()).unwrap();
        let issuer = Scripted::shaped(Shape::honest(SSH_END));

        let linked = fixture.ensure(&issuer);

        assert!(
            matches!(linked, Err(X509Error::NotARegularFile { .. })),
            "{linked:?}"
        );
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "target");

        fs::remove_file(fixture.key_path()).unwrap();
        fixture.ensure(&issuer).unwrap();
        for exposed in [0o640, 0o604, 0o620] {
            fs::set_permissions(fixture.key_path(), fs::Permissions::from_mode(exposed)).unwrap();
            let outcome = fixture.ensure(&issuer);
            let message = outcome
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default();
            assert!(
                matches!(outcome, Err(X509Error::ExposedFile { .. })),
                "{exposed:o}"
            );
            assert!(
                message.contains(&format!("chmod 600 {}", fixture.key_path().display())),
                "{message}"
            );
        }
        fs::set_permissions(fixture.key_path(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(fixture.store.x509_dir(), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            fixture.ensure(&issuer),
            Err(X509Error::ExposedDirectory { .. })
        ));
        assert_eq!(issuer.calls.get(), 1);

        let euid = geteuid().as_raw();
        let facts = |owner, mode| FileFacts {
            regular: true,
            owner,
            mode,
            len: 10,
        };
        let path = Path::new("/p/key.pem");
        assert!(refuse_unsafe(path, &facts(euid, 0o600), euid, Secrecy::Secret).is_ok());
        assert!(matches!(
            refuse_unsafe(
                path,
                &facts(euid.wrapping_add(1), 0o600),
                euid,
                Secrecy::Secret
            ),
            Err(X509Error::ForeignOwner { .. })
        ));
        assert!(matches!(
            refuse_unsafe(
                path,
                &facts(euid.wrapping_add(1), 0o644),
                euid,
                Secrecy::Public
            ),
            Err(X509Error::ForeignOwner { .. })
        ));
        assert!(refuse_unsafe(path, &facts(euid, 0o644), euid, Secrecy::Public).is_ok());
    }

    #[test]
    fn a_damaged_or_linked_x509_directory_and_a_damaged_key_are_never_replaced() {
        let fixture = Fixture::new(SSH_END);
        let issuer = Scripted::shaped(Shape::honest(SSH_END));
        let elsewhere = fixture.store.home().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        symlink(&elsewhere, fixture.store.x509_dir()).unwrap();

        let linked = fixture.ensure(&issuer);

        assert!(
            matches!(linked, Err(X509Error::NotADirectory { .. })),
            "{linked:?}"
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);

        fs::remove_file(fixture.store.x509_dir()).unwrap();
        fs::create_dir(fixture.store.x509_dir()).unwrap();
        fs::set_permissions(fixture.store.x509_dir(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            fixture.key_path(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::set_permissions(fixture.key_path(), fs::Permissions::from_mode(0o600)).unwrap();

        let damaged = fixture.ensure(&issuer);

        assert!(
            matches!(damaged, Err(X509Error::CorruptKey { .. })),
            "{damaged:?}"
        );
        assert_eq!(
            fs::read_to_string(fixture.key_path()).unwrap(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        );
        assert_eq!(issuer.calls.get(), 0);
    }

    #[test]
    fn a_server_that_does_not_issue_is_named_and_other_failures_are_not_retried() {
        type Expected = fn(&X509Error) -> bool;
        let cases: [(ApiError, Expected); 3] = [
            (ApiError::Rejected { status: 404 }, |err| {
                matches!(err, X509Error::NotOffered)
            }),
            (ApiError::NotConfigured, |err| {
                matches!(err, X509Error::NotOffered)
            }),
            (ApiError::Rejected { status: 500 }, |err| {
                matches!(err, X509Error::Api(ApiError::Rejected { status: 500 }))
            }),
        ];
        for (failure, expected) in cases {
            let fixture = Fixture::new(SSH_END);
            let issuer = Scripted::new(move |_| Err(failure));

            let err = fixture.ensure(&issuer).unwrap_err();

            assert!(expected(&err), "{err:?}");
            assert_eq!(issuer.calls.get(), 1);
        }
        assert_eq!(
            X509Error::NotOffered.to_string(),
            "this server does not issue X.509 certificates"
        );
    }

    #[test]
    fn a_foreign_lock_stops_before_any_request() {
        let fixture = Fixture::new(SSH_END);
        let issuer = Scripted::shaped(Shape::honest(SSH_END));
        let other = Fixture::new(SSH_END);
        let foreign = ensure_x509_with(&fixture.store, &other.lock, &issuer, NOW);
        assert!(matches!(foreign, Err(X509Error::ForeignLock)));
        assert_eq!(issuer.calls.get(), 0);
    }

    #[test]
    fn the_identity_is_read_back_and_a_damaged_or_foreign_certificate_is_refused() {
        let fixture = Fixture::new(SSH_END);
        let issued = fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();

        let identity = super::read_identity(&issued).unwrap();

        assert_eq!(identity.valid_before, SSH_END);
        assert_eq!(
            identity.key_pem(),
            fs::read_to_string(fixture.key_path()).unwrap()
        );
        assert_eq!(
            identity.certificate_pem(),
            fs::read_to_string(fixture.cert_path()).unwrap()
        );
        assert!(!format!("{identity:?}").contains("PRIVATE KEY"));
        let mut foreign = Shape::honest(SSH_END);
        foreign.other_key = true;
        let der = STANDARD
            .decode(certificate(&[], &foreign).certificate_der)
            .unwrap();
        let replacements = [
            super::pem_encode("CERTIFICATE", &der).as_str().to_owned(),
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_owned(),
        ];
        for replacement in replacements {
            fs::write(fixture.cert_path(), &replacement).unwrap();
            let refused = super::read_identity(&issued);
            assert!(
                matches!(refused, Err(X509Error::DamagedCertificate { .. })),
                "{refused:?}"
            );
        }
        fs::remove_file(fixture.cert_path()).unwrap();
        assert!(matches!(
            super::read_identity(&issued),
            Err(X509Error::Io { action: "read", .. })
        ));
    }

    #[test]
    fn logout_wipes_the_key_and_removes_the_x509_directory() {
        let fixture = Fixture::new(SSH_END);
        fixture
            .ensure(&Scripted::shaped(Shape::honest(SSH_END)))
            .unwrap();
        let witness = fixture.store.home().join("witness");
        fs::hard_link(fixture.key_path(), &witness).unwrap();
        let length = fs::metadata(&witness).unwrap().len();

        let cleared = fixture.store.clear().unwrap();

        assert!(cleared.removed_any);
        assert!(!cleared.directory_kept);
        assert!(!fixture.store.x509_dir().exists());
        assert!(!fixture.store.dir().exists());
        let wiped = fs::read(&witness).unwrap();
        assert_eq!(u64::try_from(wiped.len()).unwrap(), length);
        assert!(wiped.iter().all(|byte| *byte == 0));
    }
}
