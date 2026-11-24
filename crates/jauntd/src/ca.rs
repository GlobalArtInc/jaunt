use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use jaunt_ca::{
    AgeIdentity, CaKind, Committed, FileBackend, IDENTITY_FILE_VAR, IDENTITY_VAR, StagingDir,
};

use crate::config;

const CA_DIR: &str = "ca";
const STAGING_PREFIX: &str = "ca.staging";
const IDENTITY_FILE: &str = "age-identity.txt";

type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

#[derive(Clone, Copy)]
enum IdentitySource {
    Environment,
    Generate,
}

struct Initialized {
    user_ca: String,
    host_ca: String,
    identity_file: Option<PathBuf>,
    warnings: Vec<String>,
}

struct Output {
    code: u8,
    stdout: String,
    stderr: String,
}

pub fn init(config_path: &Path, generate_identity: bool) -> ExitCode {
    let config = match config::load(config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let output = run(&config.data_dir, generate_identity, &|name| {
        std::env::var_os(name)
    });
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

fn run(data_dir: &Path, generate_identity: bool, env: EnvLookup<'_>) -> Output {
    let source = if generate_identity {
        IdentitySource::Generate
    } else {
        IdentitySource::Environment
    };
    match init_authorities(data_dir, source, env) {
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
    Output {
        code: 0,
        stdout: format!(
            "user-ca {}\nhost-ca {}\n",
            initialized.user_ca, initialized.host_ca
        ),
        stderr,
    }
}

fn init_authorities(
    data_dir: &Path,
    source: IdentitySource,
    env: EnvLookup<'_>,
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
    install(staging, &ca_dir, provided)
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
    for kind in [CaKind::User, CaKind::Host] {
        let initialized =
            FileBackend::is_initialized(ca_dir, kind).map_err(|err| err.to_string())?;
        if initialized {
            return Err(format!(
                "{}: the {kind} certificate authority is already initialized, nothing was changed",
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
) -> Result<Initialized, String> {
    let built = populate(staging.path(), provided).and_then(|mut initialized| {
        let committed = staging.commit(ca_dir).map_err(|err| err.to_string())?;
        initialized.warnings = commit_warnings(committed);
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
    committed
        .sync_failure
        .map(|err| {
            format!(
                "warning: {err}; the certificate authority is in place but may not be durable on disk"
            )
        })
        .into_iter()
        .collect()
}

fn populate(staging: &Path, provided: Option<AgeIdentity>) -> Result<Initialized, String> {
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
    Ok(Initialized {
        user_ca: user.to_openssh().map_err(|err| err.to_string())?,
        host_ca: host.to_openssh().map_err(|err| err.to_string())?,
        identity_file,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};

    use jaunt_ca::{
        AgeIdentity, CaError, CaKind, Committed, FileBackend, IDENTITY_FILE_VAR, IDENTITY_VAR,
        StagingDir,
    };

    use super::{
        CA_DIR, IDENTITY_FILE, IdentitySource, Initialized, Output, STAGING_PREFIX,
        commit_warnings, init_authorities, install, render, run,
    };

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

    fn operator_identity(dir: &Path) -> (AgeIdentity, PathBuf) {
        let path = dir.join("operator-identity.txt");
        let identity = AgeIdentity::generate();
        identity.write_new_file(&path).unwrap();
        (identity, path)
    }

    fn run_with_identity_file(data_dir: &Path, identity_file: &Path) -> Output {
        run(data_dir, false, &|name| {
            (name == IDENTITY_FILE_VAR).then(|| identity_file.as_os_str().to_owned())
        })
    }

    #[test]
    fn generated_identity_initializes_both_authorities() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let initialized = init_authorities(&data_dir, IdentitySource::Generate, &no_env).unwrap();
        assert!(initialized.user_ca.starts_with("ssh-ed25519 "));
        assert!(initialized.host_ca.starts_with("ssh-ed25519 "));
        assert_ne!(initialized.user_ca, initialized.host_ca);

        let ca_dir = data_dir.join(CA_DIR);
        assert_eq!(initialized.identity_file, Some(ca_dir.join(IDENTITY_FILE)));
        assert_eq!(entries(&data_dir), [CA_DIR]);
        let identity = AgeIdentity::read_file(&ca_dir.join(IDENTITY_FILE)).unwrap();
        for kind in [CaKind::User, CaKind::Host] {
            assert!(FileBackend::load(&ca_dir, kind, &identity).is_ok());
        }
    }

    #[test]
    fn initialized_directory_is_left_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        init_authorities(&data_dir, IdentitySource::Generate, &no_env).unwrap();
        let ca_dir = data_dir.join(CA_DIR);
        let identity_before = fs::read(ca_dir.join(IDENTITY_FILE)).unwrap();
        let (user_before, host_before) =
            (entries(&ca_dir.join("user")), entries(&ca_dir.join("host")));

        let err = init_authorities(&data_dir, IdentitySource::Generate, &no_env)
            .err()
            .unwrap();
        assert!(err.contains("already initialized"));
        assert_eq!(entries(&data_dir), [CA_DIR]);
        assert_eq!(
            fs::read(ca_dir.join(IDENTITY_FILE)).unwrap(),
            identity_before
        );
        assert_eq!(entries(&ca_dir.join("user")), user_before);
        assert_eq!(entries(&ca_dir.join("host")), host_before);
    }

    #[test]
    fn failure_on_the_second_authority_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let ca_dir = data_dir.join(CA_DIR);

        let staging = StagingDir::create(&data_dir, STAGING_PREFIX).unwrap();
        fs::write(staging.path().join("host"), b"in the way").unwrap();
        let staging_path = staging.path().to_path_buf();

        let err = install(staging, &ca_dir, None).err().unwrap();
        assert!(err.contains("host"));
        assert!(!ca_dir.exists());
        assert!(!staging_path.exists());
        assert!(entries(&data_dir).is_empty());

        init_authorities(&data_dir, IdentitySource::Generate, &no_env).unwrap();
        assert_eq!(entries(&data_dir), [CA_DIR]);
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
        let initialized = install(staging, &ca_dir, Some(provided)).unwrap();
        assert!(initialized.identity_file.is_none());
        assert_eq!(entries(&ca_dir), ["host", "user"]);
        for kind in [CaKind::User, CaKind::Host] {
            assert!(FileBackend::load(&ca_dir, kind, &identity).is_ok());
        }
    }

    #[test]
    fn non_empty_ca_directory_is_refused_before_any_staging() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_path_buf();
        let ca_dir = data_dir.join(CA_DIR);
        fs::create_dir(&ca_dir).unwrap();
        fs::write(ca_dir.join("stray"), b"keep").unwrap();

        let err = init_authorities(&data_dir, IdentitySource::Generate, &no_env)
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
        init_authorities(&data_dir, IdentitySource::Generate, &no_env).unwrap();
        assert_eq!(
            entries(&data_dir.join(CA_DIR)),
            ["age-identity.txt", "host", "user"]
        );
    }

    #[test]
    fn generate_identity_conflicts_with_identity_in_the_environment() {
        for variable in [IDENTITY_VAR, IDENTITY_FILE_VAR] {
            let dir = tempfile::tempdir().unwrap();
            let data_dir = dir.path().join("data");
            let output = run(&data_dir, true, &|name| {
                (name == variable).then(|| OsString::from("set"))
            });
            assert_eq!(output.code, 1, "{variable}");
            assert!(output.stdout.is_empty());
            assert!(output.stderr.contains("--generate-identity"));
            assert!(!data_dir.exists());
        }
    }

    #[test]
    fn output_lists_the_user_key_then_the_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let (identity, identity_path) = operator_identity(dir.path());

        let output = run_with_identity_file(&data_dir, &identity_path);
        assert_eq!(output.code, 0);
        assert!(output.stderr.is_empty());

        let lines: Vec<&str> = output.stdout.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(output.stdout.ends_with('\n'));
        let user = lines[0].strip_prefix("user-ca ").unwrap();
        let host = lines[1].strip_prefix("host-ca ").unwrap();
        assert_ne!(user, host);

        let ca_dir = data_dir.join(CA_DIR);
        let (user_trust, _) = FileBackend::load(&ca_dir, CaKind::User, &identity).unwrap();
        let (host_trust, _) = FileBackend::load(&ca_dir, CaKind::Host, &identity).unwrap();
        assert_eq!(user, user_trust.active().to_openssh().unwrap());
        assert_eq!(host, host_trust.active().to_openssh().unwrap());
    }

    #[test]
    fn exit_codes_follow_the_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().join("data");
        let (_, identity_path) = operator_identity(dir.path());

        let missing = run(&data_dir, false, &no_env);
        assert_eq!(missing.code, 1);
        assert!(missing.stdout.is_empty());
        assert!(!data_dir.exists());

        let conflicting = run(&data_dir, false, &|_| {
            Some(identity_path.as_os_str().to_owned())
        });
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
            identity_file: Some(PathBuf::from("/data/ca/age-identity.txt")),
            warnings,
        });
        assert_eq!(output.code, 0);
        assert_eq!(
            output.stdout,
            "user-ca ssh-ed25519 USER\nhost-ca ssh-ed25519 HOST\n"
        );
        let stderr: Vec<&str> = output.stderr.lines().collect();
        assert_eq!(stderr.len(), 2);
        assert!(stderr[0].starts_with("warning: sync directory /data"));
        assert!(stderr[1].contains("/data/ca/age-identity.txt"));
    }
}
