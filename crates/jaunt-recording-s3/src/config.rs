use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use url::Url;

pub const DEFAULT_PREFIX: &str = "recordings/";
pub const DEFAULT_PART_SIZE: usize = 8 * 1024 * 1024;
pub const MIN_PART_SIZE: usize = 5 * 1024 * 1024;
pub const MAX_PART_SIZE: usize = 128 * 1024 * 1024;
pub const DEFAULT_UPLOAD_DEADLINE: Duration = Duration::from_secs(120);
pub const MIN_UPLOAD_DEADLINE: Duration = Duration::from_secs(1);
pub const MAX_UPLOAD_DEADLINE: Duration = Duration::from_secs(3600);
pub const MAX_PREFIX_LEN: usize = 256;
pub const MAX_CREDENTIAL_FILE_BYTES: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sse {
    None,
    Aes256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Config {
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub path_style: bool,
    pub allow_insecure_http: bool,
    pub sse: Sse,
    pub conditional_put: bool,
    pub part_size: usize,
    pub upload_deadline: Duration,
}

impl S3Config {
    pub fn new(region: &str, bucket: &str) -> S3Config {
        S3Config {
            endpoint: None,
            region: region.to_owned(),
            bucket: bucket.to_owned(),
            prefix: DEFAULT_PREFIX.to_owned(),
            path_style: false,
            allow_insecure_http: false,
            sse: Sse::None,
            conditional_put: true,
            part_size: DEFAULT_PART_SIZE,
            upload_deadline: DEFAULT_UPLOAD_DEADLINE,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("the bucket name is not a valid bucket name")]
    Bucket,
    #[error("the region is empty or contains characters a region never has")]
    Region,
    #[error(
        "the prefix must be empty or a relative path of letters, digits and . _ - segments ending with a slash"
    )]
    Prefix,
    #[error("the endpoint is not a valid URL without credentials, query or fragment")]
    Endpoint,
    #[error("the endpoint uses plain http: set allow_insecure_http to accept that")]
    InsecureEndpoint,
    #[error("the part size must be between {min} and {max} bytes")]
    PartSize { min: usize, max: usize },
    #[error("the upload deadline must be between {min} and {max} seconds")]
    Deadline { min: u64, max: u64 },
    #[error("the credential file {} {reason}", path.display())]
    CredentialFile { path: PathBuf, reason: &'static str },
    #[error(
        "no credentials: set access_key_file and secret_key_file or the {0} environment variable"
    )]
    CredentialsMissing(&'static str),
    #[error("the {0} credential is empty")]
    CredentialEmpty(&'static str),
    #[error("the object store client could not be built: {0}")]
    Client(String),
}

fn bucket_is_valid(bucket: &str) -> bool {
    let bytes = bucket.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && !bucket.contains("..")
}

fn region_is_valid(region: &str) -> bool {
    !region.is_empty()
        && region.len() <= 64
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn prefix_is_valid(prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if prefix.len() > MAX_PREFIX_LEN || !prefix.ends_with('/') {
        return false;
    }
    prefix[..prefix.len() - 1].split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    })
}

impl S3Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !bucket_is_valid(&self.bucket) {
            return Err(ConfigError::Bucket);
        }
        if !region_is_valid(&self.region) {
            return Err(ConfigError::Region);
        }
        if !prefix_is_valid(&self.prefix) {
            return Err(ConfigError::Prefix);
        }
        if let Some(endpoint) = &self.endpoint {
            let url = Url::parse(endpoint).map_err(|_| ConfigError::Endpoint)?;
            let scheme_ok = matches!(url.scheme(), "http" | "https");
            if !scheme_ok
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(ConfigError::Endpoint);
            }
            if url.scheme() == "http" && !self.allow_insecure_http {
                return Err(ConfigError::InsecureEndpoint);
            }
        }
        if !(MIN_PART_SIZE..=MAX_PART_SIZE).contains(&self.part_size) {
            return Err(ConfigError::PartSize {
                min: MIN_PART_SIZE,
                max: MAX_PART_SIZE,
            });
        }
        if !(MIN_UPLOAD_DEADLINE..=MAX_UPLOAD_DEADLINE).contains(&self.upload_deadline) {
            return Err(ConfigError::Deadline {
                min: MIN_UPLOAD_DEADLINE.as_secs(),
                max: MAX_UPLOAD_DEADLINE.as_secs(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Secret {
        Secret(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(redacted)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: Secret,
    pub session_token: Option<Secret>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &"redacted")
            .field("secret_key", &self.secret_key)
            .field("session_token", &self.session_token.is_some())
            .finish()
    }
}

pub const ENV_ACCESS_KEY: &str = "AWS_ACCESS_KEY_ID";
pub const ENV_SECRET_KEY: &str = "AWS_SECRET_ACCESS_KEY";
pub const ENV_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";

fn read_credential_file(path: &Path) -> Result<String, ConfigError> {
    let fail = |reason| ConfigError::CredentialFile {
        path: path.to_path_buf(),
        reason,
    };
    let metadata = fs::metadata(path).map_err(|_| fail("cannot be read"))?;
    if !metadata.is_file() {
        return Err(fail("is not a regular file"));
    }
    if metadata.mode() & 0o007 != 0 {
        return Err(fail("is readable by everyone: restrict its mode"));
    }
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(fail("is too large for a credential"));
    }
    let text = fs::read_to_string(path).map_err(|_| fail("is not readable text"))?;
    Ok(text.trim().to_owned())
}

fn nonempty(name: &'static str, value: String) -> Result<String, ConfigError> {
    if value.is_empty() {
        Err(ConfigError::CredentialEmpty(name))
    } else {
        Ok(value)
    }
}

impl Credentials {
    pub fn from_files(
        access_key_file: &Path,
        secret_key_file: &Path,
    ) -> Result<Credentials, ConfigError> {
        let access_key = nonempty("access key", read_credential_file(access_key_file)?)?;
        let secret_key = nonempty("secret key", read_credential_file(secret_key_file)?)?;
        Ok(Credentials {
            access_key,
            secret_key: Secret(secret_key),
            session_token: None,
        })
    }

    pub fn from_env(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Credentials, ConfigError> {
        let access_key =
            lookup(ENV_ACCESS_KEY).ok_or(ConfigError::CredentialsMissing(ENV_ACCESS_KEY))?;
        let secret_key =
            lookup(ENV_SECRET_KEY).ok_or(ConfigError::CredentialsMissing(ENV_SECRET_KEY))?;
        let session_token = lookup(ENV_SESSION_TOKEN)
            .map(|token| nonempty("session token", token.trim().to_owned()))
            .transpose()?
            .map(Secret);
        Ok(Credentials {
            access_key: nonempty("access key", access_key.trim().to_owned())?,
            secret_key: Secret(nonempty("secret key", secret_key.trim().to_owned())?),
            session_token,
        })
    }

    pub fn secrets(&self) -> Vec<String> {
        let mut values = vec![self.access_key.clone(), self.secret_key.expose().to_owned()];
        if let Some(token) = &self.session_token {
            values.push(token.expose().to_owned());
        }
        values
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn base() -> S3Config {
        S3Config::new("eu-west-1", "jaunt-recordings")
    }

    #[test]
    fn a_valid_configuration_passes_and_each_bad_field_is_named() {
        assert_eq!(base().validate(), Ok(()));
        let cases: Vec<(S3Config, ConfigError)> = vec![
            (
                S3Config {
                    bucket: "AB".into(),
                    ..base()
                },
                ConfigError::Bucket,
            ),
            (
                S3Config {
                    bucket: "a..b".into(),
                    ..base()
                },
                ConfigError::Bucket,
            ),
            (
                S3Config {
                    bucket: "-abc".into(),
                    ..base()
                },
                ConfigError::Bucket,
            ),
            (
                S3Config {
                    region: String::new(),
                    ..base()
                },
                ConfigError::Region,
            ),
            (
                S3Config {
                    region: "eu west".into(),
                    ..base()
                },
                ConfigError::Region,
            ),
            (
                S3Config {
                    prefix: "/abs/".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    prefix: "no-slash".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    prefix: "a/../b/".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    prefix: "a//b/".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    prefix: "a b/".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    prefix: "caf\u{e9}/".into(),
                    ..base()
                },
                ConfigError::Prefix,
            ),
            (
                S3Config {
                    endpoint: Some("https://key:pw@s3.example".into()),
                    ..base()
                },
                ConfigError::Endpoint,
            ),
            (
                S3Config {
                    endpoint: Some("https://s3.example/?x=1".into()),
                    ..base()
                },
                ConfigError::Endpoint,
            ),
            (
                S3Config {
                    endpoint: Some("ftp://s3.example".into()),
                    ..base()
                },
                ConfigError::Endpoint,
            ),
            (
                S3Config {
                    endpoint: Some("not a url".into()),
                    ..base()
                },
                ConfigError::Endpoint,
            ),
            (
                S3Config {
                    endpoint: Some("http://s3.example".into()),
                    ..base()
                },
                ConfigError::InsecureEndpoint,
            ),
            (
                S3Config {
                    part_size: MIN_PART_SIZE - 1,
                    ..base()
                },
                ConfigError::PartSize {
                    min: MIN_PART_SIZE,
                    max: MAX_PART_SIZE,
                },
            ),
            (
                S3Config {
                    part_size: MAX_PART_SIZE + 1,
                    ..base()
                },
                ConfigError::PartSize {
                    min: MIN_PART_SIZE,
                    max: MAX_PART_SIZE,
                },
            ),
            (
                S3Config {
                    upload_deadline: Duration::ZERO,
                    ..base()
                },
                ConfigError::Deadline { min: 1, max: 3600 },
            ),
        ];
        for (config, expected) in cases {
            assert_eq!(config.validate(), Err(expected), "{config:?}");
        }
        for prefix in ["", "recordings/", "a/b-c/d.e_f/"] {
            assert_eq!(
                S3Config {
                    prefix: prefix.into(),
                    ..base()
                }
                .validate(),
                Ok(())
            );
        }
        let http = S3Config {
            endpoint: Some("http://127.0.0.1:9000".into()),
            allow_insecure_http: true,
            ..base()
        };
        assert_eq!(http.validate(), Ok(()));
    }

    #[test]
    fn credentials_come_from_files_or_the_environment_and_never_show_in_debug_or_errors() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str, mode: u32| {
            let path = dir.path().join(name);
            fs::write(&path, text).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let access = write("access", "AKIDEXAMPLE\n", 0o600);
        let secret = write("secret", "  s3cr3t-value \n", 0o640);
        let loaded = Credentials::from_files(&access, &secret).unwrap();
        assert_eq!(loaded.access_key, "AKIDEXAMPLE");
        assert_eq!(loaded.secret_key.expose(), "s3cr3t-value");
        let shown = format!("{loaded:?} {:?}", loaded.secret_key);
        assert!(
            !shown.contains("s3cr3t-value") && !shown.contains("AKIDEXAMPLE"),
            "{shown}"
        );

        let open = write("open", "s3cr3t-value", 0o644);
        let empty = write("empty", " \n", 0o600);
        let big = write("big", &"x".repeat(5000), 0o600);
        for (path, reason) in [
            (&open, "is readable by everyone: restrict its mode"),
            (&big, "is too large for a credential"),
            (&dir.path().join("missing"), "cannot be read"),
            (&dir.path().to_path_buf(), "is not a regular file"),
        ] {
            let err = Credentials::from_files(&access, path).unwrap_err();
            assert_eq!(
                err,
                ConfigError::CredentialFile {
                    path: path.clone(),
                    reason
                },
                "{err}"
            );
            assert!(!err.to_string().contains("s3cr3t-value"));
        }
        assert_eq!(
            Credentials::from_files(&access, &empty).unwrap_err(),
            ConfigError::CredentialEmpty("secret key")
        );

        let env = |name: &str| match name {
            ENV_ACCESS_KEY => Some("AKIDENV".to_owned()),
            ENV_SECRET_KEY => Some("env-secret".to_owned()),
            ENV_SESSION_TOKEN => Some("env-token".to_owned()),
            _ => None,
        };
        let from_env = Credentials::from_env(&env).unwrap();
        assert_eq!(from_env.access_key, "AKIDENV");
        assert_eq!(from_env.secrets().len(), 3);
        let none = |_: &str| None;
        assert_eq!(
            Credentials::from_env(&none).unwrap_err(),
            ConfigError::CredentialsMissing(ENV_ACCESS_KEY)
        );
    }
}
