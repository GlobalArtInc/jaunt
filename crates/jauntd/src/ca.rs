use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::SystemTime;

use jaunt_ca::{
    AgeIdentity, CaError, CaKind, CaLock, ClientCa, ClientSlot, Committed, FileBackend,
    IDENTITY_FILE_VAR, IDENTITY_VAR, InternalCa, StagingDir, TrustSet,
};

use crate::config::{self, EnvLookup};

pub const CA_DIR: &str = "ca";
const STAGING_PREFIX: &str = "ca.staging";
const IDENTITY_FILE: &str = "age-identity.txt";
const LEGACY_KINDS: [CaKind; 3] = [CaKind::User, CaKind::Host, CaKind::Internal];
const CLIENT_KINDS: [CaKind; 2] = [CaKind::UserX509, CaKind::DbClient];

#[derive(Clone, Copy)]
enum IdentitySource {
    Environment,
    Generate,
}

struct Initialized {
    user_ca: String,
    host_ca: String,
    internal_ca: String,
    client_cas: Vec<String>,
    identity_file: Option<PathBuf>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct Added {
    lines: Vec<String>,
    notes: Vec<String>,
    warnings: Vec<String>,
}

pub struct Output {
    pub code: u8,
    pub stdout: String,
    stderr: String,
}

pub struct Authorities {
    pub user: FileBackend,
    pub user_trust: TrustSet,
    pub host_trust: TrustSet,
    pub host: FileBackend,
    pub internal: InternalCa,
    pub user_x509: Option<ClientSlot>,
    pub db_client: Option<ClientSlot>,
}

pub fn load_authorities(data_dir: &Path, env: EnvLookup<'_>) -> Result<Authorities, String> {
    let ca_dir = data_dir.join(CA_DIR);
    let identity = resolve_identity(&ca_dir, env)?;
    let (user_trust, user) =
        FileBackend::load(&ca_dir, CaKind::User, &identity).map_err(|err| err.to_string())?;
    let (host_trust, host) =
        FileBackend::load(&ca_dir, CaKind::Host, &identity).map_err(|err| err.to_string())?;
    let (_internal_trust, internal_signer) =
        FileBackend::load(&ca_dir, CaKind::Internal, &identity).map_err(|err| err.to_string())?;
    let root = FileBackend::load_root_certificate(&ca_dir).map_err(|err| err.to_string())?;
    let internal =
        InternalCa::new(Arc::new(internal_signer), root).map_err(|err| err.to_string())?;
    Ok(Authorities {
        user,
        user_trust,
        host_trust,
        host,
        internal,
        user_x509: load_client(&ca_dir, CaKind::UserX509, &identity)?,
        db_client: load_client(&ca_dir, CaKind::DbClient, &identity)?,
    })
}

fn load_client(
    ca_dir: &Path,
    kind: CaKind,
    identity: &AgeIdentity,
) -> Result<Option<ClientSlot>, String> {
    if !FileBackend::is_initialized(ca_dir, kind).map_err(|err| err.to_string())? {
        return Ok(None);
    }
    ClientCa::load(ca_dir, kind, identity)
        .map(Some)
        .map_err(|err| format!("the {kind} certificate authority: {err}"))
}

pub(crate) fn resolve_identity(ca_dir: &Path, env: EnvLookup<'_>) -> Result<AgeIdentity, String> {
    let key = env(IDENTITY_VAR);
    let key_file = env(IDENTITY_FILE_VAR);
    if key.is_some() || key_file.is_some() {
        return AgeIdentity::from_sources(key, key_file).map_err(|err| err.to_string());
    }
    let generated = ca_dir.join(IDENTITY_FILE);
    match fs::metadata(&generated) {
        Ok(_) => AgeIdentity::read_file(&generated).map_err(|err| err.to_string()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(format!(
            "no age identity for the certificate authorities: set {IDENTITY_VAR} or \
             {IDENTITY_FILE_VAR}, or keep the generated identity at {}",
            generated.display()
        )),
        Err(err) => Err(format!("{}: {err}", generated.display())),
    }
}

pub fn init(config_path: &Path, generate_identity: bool) -> ExitCode {
    let config = match config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let output = run(
        &config.data_dir,
        generate_identity,
        &|name| std::env::var_os(name),
        SystemTime::now(),
    );
    emit(&output)
}

fn emit(output: &Output) -> ExitCode {
    eprint!("{}", output.stderr);
    match io::stdout().lock().write_all(output.stdout.as_bytes()) {
        Ok(()) => ExitCode::from(output.code),
        Err(err) => {
            eprintln!("cannot write to stdout: {err}");
            ExitCode::from(1)
        }
    }
}

pub fn run(
    data_dir: &Path,
    generate_identity: bool,
    env: EnvLookup<'_>,
    now: SystemTime,
) -> Output {
    let source = if generate_identity {
        IdentitySource::Generate
    } else {
        IdentitySource::Environment
    };
    match init_authorities(data_dir, source, env, now) {
        Ok(initialized) => render(&initialized),
        Err(err) => Output {
            code: 1,
            stdout: String::new(),
            stderr: format!("{err}\n"),
        },
    }
}

fn render(initialized: &Initialized) -> Output {
    let mut stderr = String::new();
    for warning in &initialized.warnings {
        stderr.push_str(warning);
        stderr.push('\n');
    }
    if let Some(path) = &initialized.identity_file {
        stderr.push_str(&format!(
            "warning: the age identity that decrypts the CA keys was written to {}; \
             move it away from the data directory and keep it secret, because anyone \
             holding both can issue certificates\n",
            path.display()
        ));
    }
    let mut stdout = format!(
        "user-ca {}\nhost-ca {}\ninternal-ca sha256:{}\n",
        initialized.user_ca, initialized.host_ca, initialized.internal_ca
    );
    for line in &initialized.client_cas {
        stdout.push_str(line);
        stdout.push('\n');
    }
    Output {
        code: 0,
        stdout,
        stderr,
    }
}

pub fn add_missing(config_path: &Path) -> ExitCode {
    let config = match config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let output = run_add_missing(
        &config.data_dir,
        &|name| std::env::var_os(name),
        SystemTime::now(),
    );
    emit(&output)
}

pub fn run_add_missing(data_dir: &Path, env: EnvLookup<'_>, now: SystemTime) -> Output {
    let mut added = Added::default();
    let outcome = add_missing_authorities(&data_dir.join(CA_DIR), env, now, &mut added);
    let mut stdout = String::new();
    for line in &added.lines {
        stdout.push_str(line);
        stdout.push('\n');
    }
    let mut stderr = String::new();
    for note in added.notes.iter().chain(&added.warnings) {
        stderr.push_str(note);
        stderr.push('\n');
    }
    match outcome {
        Ok(()) => {
            if added.lines.is_empty() && added.notes.is_empty() {
                stderr.push_str(
                    "every certificate authority is already initialized, nothing was changed\n",
                );
            } else if added.lines.is_empty() {
                stderr.push_str("every certificate authority is already initialized\n");
            }
            Output {
                code: 0,
                stdout,
                stderr,
            }
        }
        Err(err) => {
            stderr.push_str(&err);
            if !added.lines.is_empty() {
                stderr.push_str(
                    "; the authorities printed above were added, run the command again to add the rest",
                );
            }
            stderr.push('\n');
            Output {
                code: 1,
                stdout,
                stderr,
            }
        }
    }
}

fn add_missing_authorities(
    ca_dir: &Path,
    env: EnvLookup<'_>,
    now: SystemTime,
    added: &mut Added,
) -> Result<(), String> {
    for kind in LEGACY_KINDS {
        if !FileBackend::is_initialized(ca_dir, kind).map_err(|err| err.to_string())? {
            return Err(format!(
                "{}: the {kind} certificate authority is not initialized: run `jauntd ca init` \
                 first, nothing was changed",
                ca_dir.display()
            ));
        }
    }
    let lock = CaLock::acquire(ca_dir).map_err(|err| err.to_string())?;
    let identity = resolve_identity(lock.root(), env)?;
    for kind in LEGACY_KINDS {
        FileBackend::load(lock.root(), kind, &identity).map_err(|err| {
            format!("the {kind} certificate authority: {err}, nothing was changed")
        })?;
    }
    for kind in CLIENT_KINDS {
        for path in ClientCa::remove_stale_staging(&lock, kind).map_err(|err| err.to_string())? {
            added.notes.push(format!(
                "removed {}, left behind by an interrupted run",
                path.display()
            ));
        }
    }
    let recipient = identity.recipient();
    for kind in CLIENT_KINDS {
        if FileBackend::is_initialized(lock.root(), kind).map_err(|err| err.to_string())? {
            continue;
        }
        let initialized =
            ClientCa::init(lock.root(), kind, &recipient, now).map_err(|err| err.to_string())?;
        added.lines.push(format!(
            "{kind}-ca sha256:{}",
            initialized.root.sha256_hex()
        ));
        added
            .warnings
            .extend(sync_warning(initialized.sync_failure));
    }
    drop(lock);
    Ok(())
}

fn init_authorities(
    data_dir: &Path,
    source: IdentitySource,
    env: EnvLookup<'_>,
    now: SystemTime,
) -> Result<Initialized, String> {
    let ca_dir = data_dir.join(CA_DIR);
    ensure_not_initialized(&ca_dir)?;
    let provided = match source {
        IdentitySource::Environment => Some(
            AgeIdentity::from_sources(env(IDENTITY_VAR), env(IDENTITY_FILE_VAR))
                .map_err(|err| err.to_string())?,
        ),
        IdentitySource::Generate => {
            reject_identity_in_environment(env)?;
            None
        }
    };
    ensure_replaceable(&ca_dir)?;
    let staging = StagingDir::create(data_dir, STAGING_PREFIX).map_err(|err| err.to_string())?;
    install(staging, &ca_dir, provided, now)
}

fn reject_identity_in_environment(env: EnvLookup<'_>) -> Result<(), String> {
    if env(IDENTITY_VAR).is_some() || env(IDENTITY_FILE_VAR).is_some() {
        return Err(format!(
            "--generate-identity cannot be combined with {IDENTITY_VAR} or {IDENTITY_FILE_VAR}: \
             unset them or drop the flag"
        ));
    }
    Ok(())
}

fn ensure_not_initialized(ca_dir: &Path) -> Result<(), String> {
    let initialized =
        |kind: CaKind| FileBackend::is_initialized(ca_dir, kind).map_err(|err| err.to_string());
    let mut missing = Vec::new();
    for kind in CLIENT_KINDS {
        if !initialized(kind)? {
            missing.push(kind.as_str());
        }
    }
    let mut legacy_complete = true;
    for kind in LEGACY_KINDS {
        legacy_complete &= initialized(kind)?;
    }
    for kind in LEGACY_KINDS.into_iter().chain(CLIENT_KINDS) {
        if initialized(kind)? {
            let hint = if missing.is_empty() || !legacy_complete {
                String::new()
            } else {
                format!(
                    "; to add the missing {} authorities run `jauntd ca init --add-missing`",
                    missing.join(" and ")
                )
            };
            return Err(format!(
                "{}: the {kind} certificate authority is already initialized, nothing was changed{hint}",
                ca_dir.display()
            ));
        }
    }
    Ok(())
}

fn ensure_replaceable(ca_dir: &Path) -> Result<(), String> {
    match fs::read_dir(ca_dir) {
        Ok(mut entries) => match entries.next() {
            None => Ok(()),
            Some(Ok(_)) => Err(format!(
                "{}: the ca directory exists and is not empty, nothing was changed",
                ca_dir.display()
            )),
            Some(Err(err)) => Err(format!("{}: {err}", ca_dir.display())),
        },
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("{}: {err}", ca_dir.display())),
    }
}

fn install(
    mut staging: StagingDir,
    ca_dir: &Path,
    provided: Option<AgeIdentity>,
    now: SystemTime,
) -> Result<Initialized, String> {
    let built = populate(staging.path(), provided, now).and_then(|mut initialized| {
        let committed = staging.commit(ca_dir).map_err(|err| err.to_string())?;
        initialized.warnings.extend(commit_warnings(committed));
        if initialized.identity_file.is_some() {
            initialized.identity_file = Some(ca_dir.join(IDENTITY_FILE));
        }
        Ok(initialized)
    });
    match built {
        Ok(initialized) => Ok(initialized),
        Err(err) => match staging.discard() {
            Ok(()) => Err(err),
            Err(cleanup) => Err(format!("{err}; additionally, {cleanup}")),
        },
    }
}

fn commit_warnings(committed: Committed) -> Vec<String> {
    sync_warning(committed.sync_failure)
}

fn sync_warning(failure: Option<CaError>) -> Vec<String> {
    failure
        .map(|err| {
            format!(
                "warning: {err}; the certificate authority is in place but may not be durable on disk"
            )
        })
        .into_iter()
        .collect()
}

fn populate(
    staging: &Path,
    provided: Option<AgeIdentity>,
    now: SystemTime,
) -> Result<Initialized, String> {
    let (identity, identity_file) = match provided {
        Some(identity) => (identity, None),
        None => {
            let identity = AgeIdentity::generate();
            let path = staging.join(IDENTITY_FILE);
            identity
                .write_new_file(&path)
                .map_err(|err| err.to_string())?;
            (identity, Some(path))
        }
    };
    let recipient = identity.recipient();

    let user =
        FileBackend::init(staging, CaKind::User, &recipient).map_err(|err| err.to_string())?;
    let host =
        FileBackend::init(staging, CaKind::Host, &recipient).map_err(|err| err.to_string())?;
    let internal_ca = create_internal_authority(staging, &identity, now)?;
    let mut client_cas = Vec::new();
    let mut warnings = Vec::new();
    for kind in CLIENT_KINDS {
        let initialized =
            ClientCa::init(staging, kind, &recipient, now).map_err(|err| err.to_string())?;
        client_cas.push(format!(
            "{kind}-ca sha256:{}",
            initialized.root.sha256_hex()
        ));
        warnings.extend(sync_warning(initialized.sync_failure));
    }
    Ok(Initialized {
        user_ca: user.to_openssh().map_err(|err| err.to_string())?,
        host_ca: host.to_openssh().map_err(|err| err.to_string())?,
        internal_ca,
        client_cas,
        identity_file,
        warnings,
    })
}

fn create_internal_authority(
    staging: &Path,
    identity: &AgeIdentity,
    now: SystemTime,
) -> Result<String, String> {
    FileBackend::init(staging, CaKind::Internal, &identity.recipient())
        .map_err(|err| err.to_string())?;
    let (_, backend) =
        FileBackend::load(staging, CaKind::Internal, identity).map_err(|err| err.to_string())?;
    let root = InternalCa::create_root(&backend, now).map_err(|err| err.to_string())?;
    FileBackend::store_root_certificate(staging, &root.certificate_der)
        .map_err(|err| err.to_string())?;
    let internal =
        InternalCa::new(Arc::new(backend), root.certificate_der).map_err(|err| err.to_string())?;
    Ok(internal.root_sha256_hex())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use jaunt_ca::ssh_key::sha2::{Digest, Sha256};
    use std::cell::Cell;

    use jaunt_ca::{
        AgeIdentity, CaError, CaKind, CaLock, ClientCa, Committed, FileBackend, IDENTITY_FILE_VAR,
        IDENTITY_VAR, InternalCa, Signer, StagingDir,
    };

    use super::{
        CA_DIR, CLIENT_KINDS, IDENTITY_FILE, IdentitySource, Initialized, LEGACY_KINDS, Output,
        STAGING_PREFIX, commit_warnings, init_authorities, install, load_authorities, render, run,
        run_add_missing,
    };

    const ALL_SLOTS: [&str; 5] = ["db-client", "host", "internal", "user", "user-x509"];

    fn entries(path: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut found = Vec::new();
        let mut pending = vec![dir.to_path_buf()];
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    let contents = fs::read(&path).unwrap();
                    found.push((path.strip_prefix(dir).unwrap().to_path_buf(), contents));
                }
            }
        }
        found.sort();
        found
    }

    fn old_layout(data_dir: &Path) -> AgeIdentity {
        let ca_dir = data_dir.join(CA_DIR);
        let identity = AgeIdentity::generate();
        for kind in LEGACY_KINDS {
            FileBackend::init(&ca_dir, kind, &identity.recipient()).unwrap();
        }
        let (_, internal) = FileBackend::load(&ca_dir, CaKind::Internal, &identity).unwrap();
        let root = InternalCa::create_root(&internal, now()).unwrap();
        FileBackend::store_root_certificate(&ca_dir, &root.certificate_der).unwrap();
        identity
            .write_new_file(&ca_dir.join(IDENTITY_FILE))
            .unwrap();
        identity
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn operator_identity(dir: &Path) -> (AgeIdentity, PathBuf) {
        let path = dir.join("operator-identity.txt");
        let identity = AgeIdentity::generate();
        identity.write_new_file(&path).unwrap();
        (identity, path)
    }

    fn run_with_identity_file(data_dir: &Path, identity_file: &Path) -> Output {
        run(
            data_dir,
            false,
            &|name| (name == IDENTITY_FILE_VAR).then(|| identity_file.as_os_str().to_owned()),
            now(),
        )
    }

    #[test]
    fn generated_identity_initializes_every_authority() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let initialized =
            init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
        assert!(initialized.user_ca.starts_with("ssh-ed25519 "));
        assert!(initialized.host_ca.starts_with("ssh-ed25519 "));
        assert_ne!(initialized.user_ca, initialized.host_ca);

        let ca_dir = data_dir.join(CA_DIR);
        assert_eq!(initialized.identity_file, Some(ca_dir.join(IDENTITY_FILE)));
        assert_eq!(entries(&data_dir), [CA_DIR]);
        assert_eq!(
            entries(&ca_dir),
            [
                "age-identity.txt",
                "db-client",
                "host",
                "internal",
                "user",
                "user-x509"
            ]
        );
        let identity = AgeIdentity::read_file(&ca_dir.join(IDENTITY_FILE)).unwrap();
        for kind in LEGACY_KINDS {
            assert!(FileBackend::load(&ca_dir, kind, &identity).is_ok());
        }
        for kind in CLIENT_KINDS {
            assert!(ClientCa::load(&ca_dir, kind, &identity).is_ok());
        }
    }

    #[test]
    fn internal_authority_has_a_root_certificate_that_loads_back() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let initialized =
            init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
        let ca_dir = data_dir.join(CA_DIR);
        let identity = AgeIdentity::read_file(&ca_dir.join(IDENTITY_FILE)).unwrap();

        let (_, backend) = FileBackend::load(&ca_dir, CaKind::Internal, &identity).unwrap();
        let root = FileBackend::load_root_certificate(&ca_dir).unwrap();
        let internal = InternalCa::new(Arc::new(backend), root.clone()).unwrap();
        assert_eq!(internal.root_der(), root.as_slice());
        assert_eq!(internal.root_sha256_hex(), initialized.internal_ca);
        let names = entries(&ca_dir.join("internal"));
        assert_eq!(
            names
                .iter()
                .filter(|name| name.ends_with(".root.der"))
                .count(),
            1
        );
    }

    #[test]
    fn initialized_directory_is_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
        let ca_dir = data_dir.join(CA_DIR);
        let before = snapshot(&ca_dir);

        let err = init_authorities(&data_dir, IdentitySource::Generate, &no_env, now())
            .err()
            .unwrap();
        assert!(err.contains("already initialized"));
        assert!(!err.contains("--add-missing"), "{err}");
        assert_eq!(entries(&data_dir), [CA_DIR]);
        assert_eq!(snapshot(&ca_dir), before);
    }

    #[test]
    fn an_existing_internal_authority_alone_blocks_initialization() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let ca_dir = data_dir.join(CA_DIR);
        let identity = AgeIdentity::generate();
        FileBackend::init(&ca_dir, CaKind::Internal, &identity.recipient()).unwrap();
        let before = entries(&ca_dir.join("internal"));

        let err = init_authorities(&data_dir, IdentitySource::Generate, &no_env, now())
            .err()
            .unwrap();
        assert!(err.contains("the internal certificate authority is already initialized"));
        assert!(!err.contains("--add-missing"), "{err}");
        assert_eq!(entries(&data_dir), [CA_DIR]);
        assert_eq!(entries(&ca_dir), ["internal"]);
        assert_eq!(entries(&ca_dir.join("internal")), before);
    }

    #[test]
    fn failure_on_any_later_authority_leaves_nothing_behind() {
        for blocked in ["host", "internal", "user-x509", "db-client"] {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().to_path_buf();
            let ca_dir = data_dir.join(CA_DIR);

            let staging = StagingDir::create(&data_dir, STAGING_PREFIX).unwrap();
            fs::write(staging.path().join(blocked), b"in the way").unwrap();
            let staging_path = staging.path().to_path_buf();

            let err = install(staging, &ca_dir, None, now()).err().unwrap();
            assert!(err.contains(blocked), "{blocked}");
            assert!(!ca_dir.exists(), "{blocked}");
            assert!(!staging_path.exists(), "{blocked}");
            assert!(entries(&data_dir).is_empty(), "{blocked}");

            init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
            assert_eq!(entries(&data_dir), [CA_DIR]);
        }
    }

    #[test]
    fn provided_identity_is_never_written_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let ca_dir = data_dir.join(CA_DIR);
        let (identity, identity_path) = operator_identity(dir.path());
        let provided = AgeIdentity::read_file(&identity_path).unwrap();

        fs::create_dir(&data_dir).unwrap();
        let staging = StagingDir::create(&data_dir, STAGING_PREFIX).unwrap();
        let initialized = install(staging, &ca_dir, Some(provided), now()).unwrap();
        assert!(initialized.identity_file.is_none());
        assert_eq!(entries(&ca_dir), ALL_SLOTS);
        for kind in LEGACY_KINDS {
            assert!(FileBackend::load(&ca_dir, kind, &identity).is_ok());
        }
        for kind in CLIENT_KINDS {
            assert!(ClientCa::load(&ca_dir, kind, &identity).is_ok());
        }
    }

    #[test]
    fn non_empty_ca_directory_is_refused_before_any_staging() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let ca_dir = data_dir.join(CA_DIR);
        fs::create_dir(&ca_dir).unwrap();
        fs::write(ca_dir.join("stray"), b"keep").unwrap();

        let err = init_authorities(&data_dir, IdentitySource::Generate, &no_env, now())
            .err()
            .unwrap();
        assert!(err.contains("exists and is not empty"));
        assert_eq!(entries(&data_dir), [CA_DIR]);
        assert_eq!(entries(&ca_dir), ["stray"]);
    }

    #[test]
    fn empty_ca_directory_is_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        fs::create_dir(data_dir.join(CA_DIR)).unwrap();
        init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
        let mut expected = vec!["age-identity.txt"];
        expected.extend(ALL_SLOTS);
        assert_eq!(entries(&data_dir.join(CA_DIR)), expected);
    }

    #[test]
    fn generate_identity_conflicts_with_identity_in_the_environment() {
        for variable in [IDENTITY_VAR, IDENTITY_FILE_VAR] {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("data");
            let output = run(
                &data_dir,
                true,
                &|name| (name == variable).then(|| OsString::from("set")),
                now(),
            );
            assert_eq!(output.code, 1, "{variable}");
            assert!(output.stdout.is_empty());
            assert!(output.stderr.contains("--generate-identity"));
            assert!(!data_dir.exists());
        }
    }

    #[test]
    fn output_lists_the_ssh_keys_and_the_hash_of_every_root() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let (identity, identity_path) = operator_identity(dir.path());

        let output = run_with_identity_file(&data_dir, &identity_path);
        assert_eq!(output.code, 0);
        assert!(output.stderr.is_empty());

        let lines: Vec<&str> = output.stdout.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(output.stdout.ends_with('\n'));
        let user = lines[0].strip_prefix("user-ca ").unwrap();
        let host = lines[1].strip_prefix("host-ca ").unwrap();
        assert_ne!(user, host);

        let ca_dir = data_dir.join(CA_DIR);
        let (user_trust, _) = FileBackend::load(&ca_dir, CaKind::User, &identity).unwrap();
        let (host_trust, _) = FileBackend::load(&ca_dir, CaKind::Host, &identity).unwrap();
        assert_eq!(user, user_trust.active().to_openssh().unwrap());
        assert_eq!(host, host_trust.active().to_openssh().unwrap());

        let root = FileBackend::load_root_certificate(&ca_dir).unwrap();
        let expected: String = Sha256::digest(&root)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(expected.len(), 64);
        assert_eq!(lines[2], format!("internal-ca sha256:{expected}"));
        for (line, kind) in lines[3..].iter().zip(CLIENT_KINDS) {
            let slot = ClientCa::load(&ca_dir, kind, &identity).unwrap();
            assert_eq!(
                *line,
                format!("{kind}-ca sha256:{}", slot.ca.root_sha256_hex())
            );
        }
    }

    #[test]
    fn exit_codes_follow_the_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let (_, identity_path) = operator_identity(dir.path());

        let missing = run(&data_dir, false, &no_env, now());
        assert_eq!(missing.code, 1);
        assert!(missing.stdout.is_empty());
        assert!(!data_dir.exists());

        let conflicting = run(
            &data_dir,
            false,
            &|_| Some(identity_path.as_os_str().to_owned()),
            now(),
        );
        assert_eq!(conflicting.code, 1);
        assert!(conflicting.stdout.is_empty());
        assert!(!data_dir.exists());

        assert_eq!(run_with_identity_file(&data_dir, &identity_path).code, 0);

        let again = run_with_identity_file(&data_dir, &identity_path);
        assert_eq!(again.code, 1);
        assert!(again.stdout.is_empty());
        assert!(again.stderr.contains("already initialized"));
    }

    #[test]
    fn directory_sync_failure_only_adds_a_warning() {
        let failure = CaError::Io {
            op: "sync directory",
            path: PathBuf::from("/data"),
            source: io::Error::other("injected"),
        };
        let warnings = commit_warnings(Committed {
            sync_failure: Some(failure),
        });
        assert_eq!(warnings.len(), 1);
        assert!(commit_warnings(Committed { sync_failure: None }).is_empty());

        let output = render(&Initialized {
            user_ca: "ssh-ed25519 USER".to_owned(),
            host_ca: "ssh-ed25519 HOST".to_owned(),
            internal_ca: "0123abcd".to_owned(),
            client_cas: vec!["user-x509-ca sha256:4567".to_owned()],
            identity_file: Some(PathBuf::from("/data/ca/age-identity.txt")),
            warnings,
        });
        assert_eq!(output.code, 0);
        assert_eq!(
            output.stdout,
            "user-ca ssh-ed25519 USER\nhost-ca ssh-ed25519 HOST\ninternal-ca sha256:0123abcd\n\
             user-x509-ca sha256:4567\n"
        );
        let stderr: Vec<&str> = output.stderr.lines().collect();
        assert_eq!(stderr.len(), 2);
        assert!(stderr[0].starts_with("warning: sync directory /data"));
        assert!(stderr[1].contains("/data/ca/age-identity.txt"));
    }

    #[test]
    fn authorities_load_with_the_generated_identity_file() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let initialized =
            init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();

        let authorities = load_authorities(&data_dir, &no_env).unwrap();

        assert_eq!(authorities.user.kind(), CaKind::User);
        assert_eq!(authorities.host.kind(), CaKind::Host);
        assert_eq!(
            authorities.internal.root_sha256_hex(),
            initialized.internal_ca
        );
        assert_eq!(
            authorities.user.public_key().to_openssh().unwrap(),
            initialized.user_ca
        );
        assert_eq!(
            authorities.host_trust.to_authorized_lines().unwrap(),
            [initialized.host_ca]
        );
        let user_x509 = authorities.user_x509.unwrap();
        let db_client = authorities.db_client.unwrap();
        assert_eq!(user_x509.ca.kind(), CaKind::UserX509);
        assert_eq!(db_client.ca.kind(), CaKind::DbClient);
        assert_eq!(
            initialized.client_cas,
            [
                format!("user-x509-ca sha256:{}", user_x509.ca.root_sha256_hex()),
                format!("db-client-ca sha256:{}", db_client.ca.root_sha256_hex())
            ]
        );
    }

    #[test]
    fn authorities_load_with_an_identity_from_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let (_identity, identity_path) = operator_identity(dir.path());
        assert_eq!(run_with_identity_file(&data_dir, &identity_path).code, 0);
        let env =
            |name: &str| (name == IDENTITY_FILE_VAR).then(|| identity_path.as_os_str().to_owned());

        assert!(load_authorities(&data_dir, &env).is_ok());

        let err = load_authorities(&data_dir, &no_env).err().unwrap();
        assert!(err.contains(IDENTITY_VAR) && err.contains(IDENTITY_FILE_VAR));
    }

    #[test]
    fn authorities_refuse_conflicting_wrong_and_missing_identities() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        init_authorities(&data_dir, IdentitySource::Generate, &no_env, now()).unwrap();
        let (_stranger, stranger_path) = operator_identity(dir.path());

        let conflict = load_authorities(&data_dir, &|_| Some(stranger_path.as_os_str().to_owned()))
            .err()
            .unwrap();
        assert!(conflict.contains("not both"));

        let wrong = load_authorities(&data_dir, &|name| {
            (name == IDENTITY_FILE_VAR).then(|| stranger_path.as_os_str().to_owned())
        })
        .err()
        .unwrap();
        assert!(wrong.contains("could not decrypt"));

        let empty = tempfile::tempdir().unwrap();
        let uninitialized = load_authorities(empty.path(), &no_env).err().unwrap();
        assert!(uninitialized.contains("no age identity"));
    }

    #[test]
    fn an_old_directory_loads_without_the_new_authorities() {
        let dir = tempfile::tempdir().unwrap();
        old_layout(dir.path());
        let before = snapshot(&dir.path().join(CA_DIR));

        let authorities = load_authorities(dir.path(), &no_env).unwrap();

        assert!(authorities.user_x509.is_none());
        assert!(authorities.db_client.is_none());
        assert_eq!(authorities.user.kind(), CaKind::User);
        assert_eq!(snapshot(&dir.path().join(CA_DIR)), before);
    }

    #[test]
    fn add_missing_adds_only_the_new_authorities_and_a_second_run_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let ca_dir = data_dir.join(CA_DIR);
        old_layout(data_dir);
        let legacy = |ca_dir: &Path| {
            let mut kept = snapshot(ca_dir);
            kept.retain(|(path, _)| {
                !path.starts_with("user-x509")
                    && !path.starts_with("db-client")
                    && path != Path::new(".lock")
            });
            kept
        };
        let before = legacy(&ca_dir);

        let first = run_add_missing(data_dir, &no_env, now());

        assert_eq!(first.code, 0, "{}", first.stderr);
        assert!(first.stderr.is_empty(), "{}", first.stderr);
        let lines: Vec<&str> = first.stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{}", first.stdout);
        assert_eq!(legacy(&ca_dir), before);
        let mut expected = vec![".lock", "age-identity.txt"];
        expected.extend(ALL_SLOTS);
        assert_eq!(entries(&ca_dir), expected);
        let authorities = load_authorities(data_dir, &no_env).unwrap();
        for (line, slot) in lines
            .iter()
            .zip([authorities.user_x509, authorities.db_client])
        {
            let slot = slot.unwrap();
            assert_eq!(
                *line,
                format!("{}-ca sha256:{}", slot.ca.kind(), slot.ca.root_sha256_hex())
            );
        }

        let after_first = snapshot(&ca_dir);
        let second = run_add_missing(data_dir, &no_env, now());
        assert_eq!(second.code, 0, "{}", second.stderr);
        assert!(second.stdout.is_empty());
        assert!(
            second.stderr.contains("nothing was changed"),
            "{}",
            second.stderr
        );
        assert_eq!(snapshot(&ca_dir), after_first);
    }

    #[test]
    fn add_missing_creates_only_the_slot_that_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join(CA_DIR);
        let identity = old_layout(dir.path());
        ClientCa::init(&ca_dir, CaKind::UserX509, &identity.recipient(), now()).unwrap();
        let existing = snapshot(&ca_dir.join("user-x509"));

        let output = run_add_missing(dir.path(), &no_env, now());

        assert_eq!(output.code, 0, "{}", output.stderr);
        assert_eq!(output.stdout.lines().count(), 1);
        assert!(output.stdout.starts_with("db-client-ca sha256:"));
        assert_eq!(snapshot(&ca_dir.join("user-x509")), existing);
        assert!(ClientCa::load(&ca_dir, CaKind::DbClient, &identity).is_ok());
    }

    #[test]
    fn plain_init_refuses_old_and_complete_directories() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        let ca_dir = data_dir.join(CA_DIR);
        old_layout(data_dir);
        let before = snapshot(&ca_dir);

        let old = run(data_dir, true, &no_env, now());
        assert_eq!(old.code, 1);
        assert!(old.stdout.is_empty());
        assert!(old.stderr.contains("already initialized"), "{}", old.stderr);
        assert!(
            old.stderr.contains(
                "missing user-x509 and db-client authorities run `jauntd ca init --add-missing`"
            ),
            "{}",
            old.stderr
        );
        assert_eq!(snapshot(&ca_dir), before);

        assert_eq!(run_add_missing(data_dir, &no_env, now()).code, 0);
        let complete = snapshot(&ca_dir);
        let again = run(data_dir, true, &no_env, now());
        assert_eq!(again.code, 1);
        assert!(again.stderr.contains("already initialized"));
        assert!(!again.stderr.contains("--add-missing"), "{}", again.stderr);
        assert_eq!(snapshot(&ca_dir), complete);
    }

    #[test]
    fn add_missing_refuses_a_foreign_identity_and_an_uninitialized_directory() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let ca_dir = data_dir.join(CA_DIR);
        old_layout(&data_dir);
        let before = snapshot(&ca_dir);
        let (_, stranger) = operator_identity(dir.path());

        let foreign = run_add_missing(
            &data_dir,
            &|name| (name == IDENTITY_FILE_VAR).then(|| stranger.as_os_str().to_owned()),
            now(),
        );
        assert_eq!(foreign.code, 1);
        assert!(foreign.stdout.is_empty());
        assert!(
            foreign.stderr.contains("could not decrypt"),
            "{}",
            foreign.stderr
        );
        assert!(
            foreign.stderr.contains("nothing was changed"),
            "{}",
            foreign.stderr
        );
        let mut after = snapshot(&ca_dir);
        after.retain(|(path, _)| path != Path::new(".lock"));
        assert_eq!(after, before);

        let empty = dir.path().join("empty");
        let uninitialized = run_add_missing(&empty, &no_env, now());
        assert_eq!(uninitialized.code, 1);
        assert!(
            uninitialized
                .stderr
                .contains("not initialized: run `jauntd ca init` first"),
            "{}",
            uninitialized.stderr
        );
        assert!(!empty.exists());
    }

    #[test]
    fn add_missing_waits_for_no_one_and_holds_the_lock_for_its_whole_run() {
        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join(CA_DIR);
        old_layout(dir.path());

        let held = CaLock::acquire(&ca_dir).unwrap();
        let before = snapshot(&ca_dir);
        let refused = run_add_missing(dir.path(), &no_env, now());
        assert_eq!(refused.code, 1);
        assert!(refused.stdout.is_empty());
        assert!(
            refused
                .stderr
                .contains("another certificate authority command is running, nothing was changed"),
            "{}",
            refused.stderr
        );
        assert_eq!(snapshot(&ca_dir), before);
        drop(held);

        let busy_while_running = Cell::new(None);
        let probe = |name: &str| {
            if busy_while_running.get().is_none() {
                let busy = matches!(CaLock::acquire(&ca_dir), Err(CaError::LockBusy));
                busy_while_running.set(Some(busy));
            }
            no_env(name)
        };
        let added = run_add_missing(dir.path(), &probe, now());
        assert_eq!(added.code, 0, "{}", added.stderr);
        assert_eq!(busy_while_running.get(), Some(true));
    }

    #[test]
    fn a_damaged_client_slot_stops_loading_and_names_the_slot() {
        for kind in CLIENT_KINDS {
            for damage in ["truncated", "deleted"] {
                let dir = tempfile::tempdir().unwrap();
                init_authorities(dir.path(), IdentitySource::Generate, &no_env, now()).unwrap();
                let slot_dir = dir.path().join(CA_DIR).join(kind.as_str());
                let active = fs::read_to_string(slot_dir.join("active")).unwrap();
                let root = slot_dir.join(format!("{}.root.der", active.trim_end()));
                if damage == "truncated" {
                    let der = fs::read(&root).unwrap();
                    fs::write(&root, &der[..der.len() / 2]).unwrap();
                } else {
                    fs::remove_file(&root).unwrap();
                }

                let err = load_authorities(dir.path(), &no_env).err().unwrap();

                assert!(
                    err.contains(&format!("the {kind} certificate authority: ")),
                    "{kind} {damage}: {err}"
                );
                assert!(err.contains(".root.der"), "{kind} {damage}: {err}");
            }
        }
    }

    #[test]
    fn add_missing_removes_only_the_staging_directories_it_left_behind() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let ca_dir = dir.path().join(CA_DIR);
        old_layout(dir.path());
        let ours = [
            ".user-x509.staging-0123456789abcdef",
            ".db-client.staging-fedcba9876543210",
        ];
        let foreign = [
            ".user-x509.staging-0123",
            ".user-x509.staging-ABCDEF0123456789",
            ".host.staging-0123456789abcdef",
            "user-x509.staging-0123456789abcdef",
        ];
        for name in ours.iter().chain(&foreign) {
            fs::create_dir(ca_dir.join(name)).unwrap();
            fs::write(ca_dir.join(name).join("key.age"), b"sealed").unwrap();
        }
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"keep").unwrap();
        let linked = ca_dir.join(".db-client.staging-1111111111111111");
        symlink(&outside, &linked).unwrap();
        let plain_file = ca_dir.join(".user-x509.staging-2222222222222222");
        fs::write(&plain_file, b"file").unwrap();

        let first = run_add_missing(dir.path(), &no_env, now());

        assert_eq!(first.code, 0, "{}", first.stderr);
        assert_eq!(first.stdout.lines().count(), 2);
        for name in ours {
            assert!(!ca_dir.join(name).exists(), "{name}");
            assert!(first.stderr.contains(name), "{}", first.stderr);
        }
        for name in foreign {
            assert!(ca_dir.join(name).join("key.age").exists(), "{name}");
        }
        assert!(
            fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(outside.join("keep").exists());
        assert!(plain_file.is_file());

        let late = ca_dir.join(".user-x509.staging-abcdefabcdefabcd");
        fs::create_dir(&late).unwrap();
        let second = run_add_missing(dir.path(), &no_env, now());
        assert_eq!(second.code, 0, "{}", second.stderr);
        assert!(second.stdout.is_empty());
        assert!(!late.exists());
        assert!(
            second.stderr.contains("already initialized"),
            "{}",
            second.stderr
        );
        assert!(
            !second.stderr.contains("nothing was changed"),
            "{}",
            second.stderr
        );
    }
}
