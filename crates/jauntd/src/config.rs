use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jaunt_control::{AgentEndpoint, DeviceSettings, GateEndpoint, NamingError, SshSuffix};
use jaunt_oidc::{ClientSecret, DEFAULT_SCOPES, OidcConfig};
use serde::Deserialize;
use url::Url;

pub const CLIENT_SECRET_VAR: &str = "JAUNT_OIDC_CLIENT_SECRET";

const DEFAULT_CERT_TTL_SECS: u64 = 28_800;
const MIN_CERT_TTL_SECS: u64 = 60;
const MAX_CERT_TTL_SECS: u64 = 86_400;
const CALLBACK_PATH: &str = "/v1/login/callback";
const MAX_HEADER_NAME_LEN: usize = 64;
const DEFAULT_POLICY_POLL_SECS: u64 = 5;
const MIN_POLICY_POLL_SECS: u64 = 1;
const MAX_POLICY_POLL_SECS: u64 = 3600;
const DEFAULT_POLICY_DIR: &str = "policy";

pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<OsString>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub public_url: Option<String>,
    #[serde(default = "default_cert_ttl_secs")]
    pub cert_ttl_secs: u64,
    #[serde(default = "default_device_login")]
    pub device_login: bool,
    pub client_ip_header: Option<String>,
    pub ssh_suffix: Option<String>,
    pub agent_endpoint: Option<String>,
    pub policy_dir: Option<PathBuf>,
    #[serde(default = "default_policy_poll_secs")]
    pub policy_poll_secs: u64,
    pub gate_endpoint: Option<String>,
    pub oidc: Option<OidcSection>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSection {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret_file: Option<PathBuf>,
    pub scopes: Option<Vec<String>>,
    pub username_claim: Option<String>,
    pub groups_claim: Option<String>,
    pub require_verified_email: Option<bool>,
    pub extra_root_certificates_file: Option<PathBuf>,
}

pub struct RunSettings {
    pub data_dir: PathBuf,
    pub listen: SocketAddr,
    pub cert_ttl: Duration,
    pub device: DeviceSettings,
    pub ssh_suffix: SshSuffix,
    pub gate_endpoint: Option<GateEndpoint>,
    pub agent_endpoint: AgentEndpoint,
    pub policy_dir: PathBuf,
    pub policy_poll: Duration,
    pub oidc: OidcConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("public_url is required to run the daemon")]
    MissingPublicUrl,
    #[error("public_url {0}")]
    InvalidPublicUrl(&'static str),
    #[error("cert_ttl_secs must be between {MIN_CERT_TTL_SECS} and {MAX_CERT_TTL_SECS}")]
    CertTtlOutOfRange,
    #[error("policy_poll_secs must be between {MIN_POLICY_POLL_SECS} and {MAX_POLICY_POLL_SECS}")]
    PolicyPollOutOfRange,
    #[error("client_ip_header must be a header name of letters, digits and hyphens")]
    InvalidClientIpHeader,
    #[error("ssh_suffix is required to run the daemon")]
    MissingSshSuffix,
    #[error("ssh_suffix: {0}")]
    InvalidSshSuffix(#[source] NamingError),
    #[error("agent_endpoint is required to run the daemon")]
    MissingAgentEndpoint,
    #[error("agent_endpoint: {0}")]
    InvalidAgentEndpoint(#[source] NamingError),
    #[error("gate_endpoint: {0}")]
    InvalidGateEndpoint(#[source] NamingError),
    #[error("the oidc section is required to run the daemon")]
    MissingOidc,
    #[error(
        "the oidc client secret must come from exactly one source, but both \
         oidc.client_secret_file and {CLIENT_SECRET_VAR} are set"
    )]
    AmbiguousClientSecret,
    #[error(
        "the oidc client secret is missing: set oidc.client_secret_file or {CLIENT_SECRET_VAR}"
    )]
    MissingClientSecret,
    #[error("{CLIENT_SECRET_VAR} is not valid unicode")]
    ClientSecretNotUnicode,
    #[error("the oidc client secret is empty")]
    EmptyClientSecret,
    #[error("{}: {source}", path.display())]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8443))
}

fn default_cert_ttl_secs() -> u64 {
    DEFAULT_CERT_TTL_SECS
}

fn default_device_login() -> bool {
    true
}

fn default_policy_poll_secs() -> u64 {
    DEFAULT_POLICY_POLL_SECS
}

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    let options = serde_saphyr::options! { with_snippet: false };
    serde_saphyr::from_str_with_options(&text, options)
        .map_err(|err| format!("{}: {err}", path.display()))
}

impl Config {
    pub fn into_run_settings(self, env: EnvLookup<'_>) -> Result<RunSettings, ConfigError> {
        let public_url = self.public_url.ok_or(ConfigError::MissingPublicUrl)?;
        let origin = validate_public_url(&public_url)?;
        if !(MIN_CERT_TTL_SECS..=MAX_CERT_TTL_SECS).contains(&self.cert_ttl_secs) {
            return Err(ConfigError::CertTtlOutOfRange);
        }
        if !(MIN_POLICY_POLL_SECS..=MAX_POLICY_POLL_SECS).contains(&self.policy_poll_secs) {
            return Err(ConfigError::PolicyPollOutOfRange);
        }
        let client_ip_header = self
            .client_ip_header
            .map(|name| validate_header_name(&name))
            .transpose()?;
        let ssh_suffix = self.ssh_suffix.ok_or(ConfigError::MissingSshSuffix)?;
        let ssh_suffix = SshSuffix::parse(&ssh_suffix).map_err(ConfigError::InvalidSshSuffix)?;
        let agent_endpoint = self
            .agent_endpoint
            .ok_or(ConfigError::MissingAgentEndpoint)?;
        let agent_endpoint =
            AgentEndpoint::parse(&agent_endpoint).map_err(ConfigError::InvalidAgentEndpoint)?;
        let gate_endpoint = self
            .gate_endpoint
            .map(|text| GateEndpoint::parse(&text).map_err(ConfigError::InvalidGateEndpoint))
            .transpose()?;
        let section = self.oidc.ok_or(ConfigError::MissingOidc)?;
        let client_secret = read_client_secret(section.client_secret_file.as_deref(), env)?;

        let mut oidc = OidcConfig::new(
            section.issuer_url,
            section.client_id,
            client_secret,
            format!("{origin}{CALLBACK_PATH}"),
        );
        oidc.scopes = section.scopes.unwrap_or_else(|| {
            DEFAULT_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect()
        });
        if let Some(claim) = section.username_claim {
            oidc.username_claim = claim;
        }
        if let Some(claim) = section.groups_claim {
            oidc.groups_claim = claim;
        }
        if let Some(required) = section.require_verified_email {
            oidc.require_verified_email = required;
        }
        if let Some(path) = section.extra_root_certificates_file {
            let pem = std::fs::read_to_string(&path)
                .map_err(|source| ConfigError::ReadFile { path, source })?;
            oidc.extra_root_certificates_pem = vec![pem];
        }

        let policy_dir = self
            .policy_dir
            .unwrap_or_else(|| self.data_dir.join(DEFAULT_POLICY_DIR));
        Ok(RunSettings {
            data_dir: self.data_dir,
            listen: self.listen,
            cert_ttl: Duration::from_secs(self.cert_ttl_secs),
            device: DeviceSettings {
                enabled: self.device_login,
                public_origin: origin,
                client_ip_header,
            },
            ssh_suffix,
            gate_endpoint,
            agent_endpoint,
            policy_dir,
            policy_poll: Duration::from_secs(self.policy_poll_secs),
            oidc,
        })
    }
}

fn validate_public_url(text: &str) -> Result<String, ConfigError> {
    let invalid = ConfigError::InvalidPublicUrl;
    if text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("must not contain whitespace or control characters"));
    }
    let url = Url::parse(text).map_err(|_| invalid("is not a valid url"))?;
    if url.scheme() != "https" {
        return Err(invalid("must use https"));
    }
    if url.host_str().is_none() {
        return Err(invalid("must name a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("must not contain a query or a fragment"));
    }
    if text.ends_with('/') {
        return Err(invalid("must not end with a slash"));
    }
    if url.path() != "/" {
        return Err(invalid("must not contain a path"));
    }
    Ok(url.origin().ascii_serialization())
}

fn validate_header_name(text: &str) -> Result<String, ConfigError> {
    let valid = !text.is_empty()
        && text.len() <= MAX_HEADER_NAME_LEN
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
    if valid {
        Ok(text.to_ascii_lowercase())
    } else {
        Err(ConfigError::InvalidClientIpHeader)
    }
}

fn read_client_secret(
    file: Option<&Path>,
    env: EnvLookup<'_>,
) -> Result<ClientSecret, ConfigError> {
    let from_env = env(CLIENT_SECRET_VAR);
    let value = match (file, from_env) {
        (Some(_), Some(_)) => return Err(ConfigError::AmbiguousClientSecret),
        (None, None) => return Err(ConfigError::MissingClientSecret),
        (None, Some(value)) => value
            .into_string()
            .map_err(|_| ConfigError::ClientSecretNotUnicode)?,
        (Some(path), None) => {
            let text = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
                path: path.to_path_buf(),
                source,
            })?;
            text.trim_end_matches(['\r', '\n']).to_owned()
        }
    };
    if value.is_empty() {
        return Err(ConfigError::EmptyClientSecret);
    }
    Ok(ClientSecret::new(value))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::{CLIENT_SECRET_VAR, Config, ConfigError, load};

    const SECRET: &str = "s3cr3t-value-that-must-never-be-printed";

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn secret_env(name: &str) -> Option<OsString> {
        (name == CLIENT_SECRET_VAR).then(|| OsString::from(SECRET))
    }

    fn parse(extra: &str) -> Config {
        let text = format!(
            "data_dir: /var/lib/jaunt\npublic_url: https://jaunt.example.com\n\
             ssh_suffix: jaunt.example.com\nagent_endpoint: agents.example.com:443\n\
             oidc:\n  issuer_url: https://idp.example.com\n  client_id: jaunt\n{extra}"
        );
        serde_saphyr::from_str(&text).unwrap()
    }

    fn secret_file(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("client-secret");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn a_data_dir_alone_is_a_valid_config_with_defaults() {
        let config: Config = serde_saphyr::from_str("data_dir: /var/lib/jaunt\n").unwrap();
        assert_eq!(config.listen.to_string(), "127.0.0.1:8443");
        assert_eq!(config.cert_ttl_secs, 28_800);
        assert!(config.public_url.is_none() && config.oidc.is_none());
        assert!(config.ssh_suffix.is_none() && config.agent_endpoint.is_none());
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        assert!(serde_saphyr::from_str::<Config>("data_dir: /d\nextra: 1\n").is_err());
        let nested = "data_dir: /d\noidc:\n  issuer_url: https://i\n  client_id: c\n  extra: 1\n";
        assert!(serde_saphyr::from_str::<Config>(nested).is_err());
        assert!(serde_saphyr::from_str::<Config>("{}\n").is_err());
    }

    #[test]
    fn load_rejects_missing_file() {
        assert!(load(Path::new("/nonexistent/jauntd-missing.yaml")).is_err());
    }

    #[test]
    fn load_errors_never_echo_a_secret_written_in_the_wrong_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("jauntd.yaml");
        let misplaced = [
            format!(
                "data_dir: /d
oidc:
  issuer_url: https://i
  client_id: c
  client_secret: {SECRET}
"
            ),
            format!(
                "data_dir: /d
client_secret: {SECRET}
"
            ),
            format!(
                "data_dir: /d
cert_ttl_secs: {SECRET}
"
            ),
        ];
        for text in misplaced {
            std::fs::write(&path, &text).unwrap();
            let err = load(&path).err().expect("the config must be refused");
            assert!(!err.contains(SECRET), "{err}");
            assert!(!format!("{err:?}").contains(SECRET), "{err:?}");
            assert!(err.contains(&path.display().to_string()), "{err}");
        }
    }

    #[test]
    fn a_complete_config_becomes_run_settings() {
        let settings = parse("  scopes: [openid, email]\n  require_verified_email: false\n")
            .into_run_settings(&secret_env)
            .unwrap();
        assert_eq!(settings.cert_ttl, Duration::from_secs(28_800));
        assert_eq!(settings.listen.to_string(), "127.0.0.1:8443");
        assert_eq!(
            settings.oidc.redirect_url,
            "https://jaunt.example.com/v1/login/callback"
        );
        assert_eq!(settings.oidc.scopes, ["openid", "email"]);
        assert!(!settings.oidc.require_verified_email);
        assert_eq!(settings.oidc.client_secret.expose(), SECRET);
    }

    #[test]
    fn run_requires_public_url_and_the_oidc_section() {
        let no_url: Config = serde_saphyr::from_str(
            "data_dir: /d\noidc:\n  issuer_url: https://i\n  client_id: c\n",
        )
        .unwrap();
        assert!(matches!(
            no_url.into_run_settings(&secret_env),
            Err(ConfigError::MissingPublicUrl)
        ));
        let no_oidc: Config = serde_saphyr::from_str(
            "data_dir: /d\npublic_url: https://jaunt.example.com\n\
             ssh_suffix: jaunt.example.com\nagent_endpoint: agents.example.com:443\n",
        )
        .unwrap();
        assert!(matches!(
            no_oidc.into_run_settings(&secret_env),
            Err(ConfigError::MissingOidc)
        ));
    }

    #[test]
    fn run_requires_a_valid_ssh_suffix_and_agent_endpoint() {
        let settings = parse("").into_run_settings(&secret_env).unwrap();
        assert_eq!(settings.ssh_suffix.as_str(), "jaunt.example.com");
        assert_eq!(settings.agent_endpoint.as_str(), "agents.example.com:443");

        let mut no_suffix = parse("");
        no_suffix.ssh_suffix = None;
        assert!(matches!(
            no_suffix.into_run_settings(&secret_env),
            Err(ConfigError::MissingSshSuffix)
        ));
        let mut no_endpoint = parse("");
        no_endpoint.agent_endpoint = None;
        assert!(matches!(
            no_endpoint.into_run_settings(&secret_env),
            Err(ConfigError::MissingAgentEndpoint)
        ));
        for suffix in [
            "",
            "Jaunt.Example.com",
            ".example.com",
            "a b.example.com",
            "*.example.com",
        ] {
            let mut config = parse("");
            config.ssh_suffix = Some(suffix.to_owned());
            assert!(
                matches!(
                    config.into_run_settings(&secret_env),
                    Err(ConfigError::InvalidSshSuffix(_))
                ),
                "{suffix:?}"
            );
        }
        for endpoint in [
            "agents.example.com",
            "agents.example.com:0",
            ":443",
            "https://a.example.com:443",
            "A.example.com:443",
        ] {
            let mut config = parse("");
            config.agent_endpoint = Some(endpoint.to_owned());
            assert!(
                matches!(
                    config.into_run_settings(&secret_env),
                    Err(ConfigError::InvalidAgentEndpoint(_))
                ),
                "{endpoint:?}"
            );
        }
    }

    #[test]
    fn the_gate_endpoint_is_optional_defaults_to_port_22_and_is_lowercased() {
        let absent = parse("").into_run_settings(&secret_env).unwrap();
        assert!(absent.gate_endpoint.is_none());

        for (given, host, port) in [
            ("gate.example.com", "gate.example.com", 22),
            ("gate.example.com:2222", "gate.example.com", 2222),
            ("Gate.Example.COM:65535", "gate.example.com", 65535),
            ("192.0.2.10:1", "192.0.2.10", 1),
            ("[2001:db8::1]:2200", "2001:db8::1", 2200),
        ] {
            let settings = parse(&format!("gate_endpoint: \"{given}\"\n"))
                .into_run_settings(&secret_env)
                .unwrap();
            let gate = settings.gate_endpoint.unwrap();
            assert_eq!((gate.host(), gate.port()), (host, port), "{given:?}");
        }

        for given in [
            "",
            "gate.example.com:0",
            "gate.example.com:65536",
            "gate.example.com:ssh",
            "gate example.com",
            "ssh://gate.example.com",
            "jaunt@gate.example.com",
            "::1",
            "gate.example.com\nProxyCommand x",
        ] {
            let mut config = parse("");
            config.gate_endpoint = Some(given.to_owned());
            assert!(
                matches!(
                    config.into_run_settings(&secret_env),
                    Err(ConfigError::InvalidGateEndpoint(_))
                ),
                "{given:?}"
            );
        }
    }

    #[test]
    fn public_url_must_be_a_bare_https_origin() {
        let accepted = [
            ("https://jaunt.example.com", "https://jaunt.example.com"),
            (
                "https://jaunt.example.com:8443",
                "https://jaunt.example.com:8443",
            ),
        ];
        for (given, origin) in accepted {
            let mut config = parse("");
            config.public_url = Some(given.to_owned());
            let settings = config.into_run_settings(&secret_env).unwrap();
            assert_eq!(
                settings.oidc.redirect_url,
                format!("{origin}/v1/login/callback")
            );
        }
        let rejected = [
            "http://jaunt.example.com",
            "https://jaunt.example.com/",
            "https://jaunt.example.com/base",
            "https://jaunt.example.com?x=1",
            "https://jaunt.example.com#top",
            "https://user:pass@jaunt.example.com",
            "https://jaunt.example.com ",
            " https://jaunt.example.com",
            "jaunt.example.com",
            "",
        ];
        for given in rejected {
            let mut config = parse("");
            config.public_url = Some(given.to_owned());
            assert!(
                matches!(
                    config.into_run_settings(&secret_env),
                    Err(ConfigError::InvalidPublicUrl(_))
                ),
                "{given:?}"
            );
        }
    }

    #[test]
    fn device_login_is_on_by_default_and_can_be_switched_off() {
        let defaults = parse("").into_run_settings(&secret_env).unwrap();
        assert!(defaults.device.enabled);
        assert_eq!(defaults.device.client_ip_header, None);
        assert_eq!(defaults.device.public_origin, "https://jaunt.example.com");

        let off = parse("device_login: false\n")
            .into_run_settings(&secret_env)
            .unwrap();
        assert!(!off.device.enabled);
        let explicit_on = parse("device_login: true\n")
            .into_run_settings(&secret_env)
            .unwrap();
        assert!(explicit_on.device.enabled);
    }

    #[test]
    fn the_client_ip_header_is_a_plain_header_name_and_is_lowercased() {
        let accepted = [
            ("x-forwarded-for", "x-forwarded-for"),
            ("X-Real-IP", "x-real-ip"),
            ("CF-Connecting-IP", "cf-connecting-ip"),
        ];
        for (given, normalised) in accepted {
            let settings = parse(&format!("client_ip_header: {given}\n"))
                .into_run_settings(&secret_env)
                .unwrap();
            assert_eq!(
                settings.device.client_ip_header.as_deref(),
                Some(normalised)
            );
        }
        let too_long = "a".repeat(65);
        let rejected = [
            "",
            "x forwarded",
            "x_forwarded",
            "x:forwarded",
            "x-for\u{e9}",
            too_long.as_str(),
        ];
        for given in rejected {
            let mut config = parse("");
            config.client_ip_header = Some(given.to_owned());
            assert!(
                matches!(
                    config.into_run_settings(&secret_env),
                    Err(ConfigError::InvalidClientIpHeader)
                ),
                "{given:?}"
            );
        }
    }

    #[test]
    fn the_policy_directory_defaults_into_the_data_dir_and_can_be_moved() {
        let defaults = parse("").into_run_settings(&secret_env).unwrap();
        assert_eq!(defaults.policy_dir, Path::new("/var/lib/jaunt/policy"));
        assert_eq!(defaults.policy_poll, Duration::from_secs(5));

        let moved = parse("policy_dir: /etc/jaunt/policy\n")
            .into_run_settings(&secret_env)
            .unwrap();
        assert_eq!(moved.policy_dir, Path::new("/etc/jaunt/policy"));
    }

    #[test]
    fn policy_poll_secs_is_bounded() {
        for (secs, ok) in [
            (0, false),
            (1, true),
            (5, true),
            (3600, true),
            (3601, false),
        ] {
            let mut config = parse("");
            config.policy_poll_secs = secs;
            let result = config.into_run_settings(&secret_env);
            assert_eq!(result.is_ok(), ok, "{secs}");
            match result {
                Ok(settings) => assert_eq!(settings.policy_poll, Duration::from_secs(secs)),
                Err(err) => assert!(matches!(err, ConfigError::PolicyPollOutOfRange), "{err}"),
            }
        }
    }

    #[test]
    fn cert_ttl_secs_is_bounded() {
        for (ttl, ok) in [
            (59, false),
            (60, true),
            (86_400, true),
            (86_401, false),
            (0, false),
        ] {
            let mut config = parse("");
            config.cert_ttl_secs = ttl;
            let result = config.into_run_settings(&secret_env);
            assert_eq!(result.is_ok(), ok, "{ttl}");
            if !ok {
                assert!(matches!(result, Err(ConfigError::CertTtlOutOfRange)));
            }
        }
    }

    #[test]
    fn exactly_one_client_secret_source_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), &format!("{SECRET}\n"));
        let from_file = format!("  client_secret_file: {}\n", path.display());

        let file_only = parse(&from_file).into_run_settings(&no_env).unwrap();
        assert_eq!(file_only.oidc.client_secret.expose(), SECRET);

        assert!(matches!(
            parse(&from_file).into_run_settings(&secret_env),
            Err(ConfigError::AmbiguousClientSecret)
        ));
        assert!(matches!(
            parse("").into_run_settings(&no_env),
            Err(ConfigError::MissingClientSecret)
        ));
    }

    #[test]
    fn empty_or_unreadable_secrets_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let empty = secret_file(
            dir.path(),
            "
",
        );
        let from_empty = format!(
            "  client_secret_file: {}
",
            empty.display()
        );
        assert!(matches!(
            parse(&from_empty).into_run_settings(&no_env),
            Err(ConfigError::EmptyClientSecret)
        ));
        let missing = format!(
            "  client_secret_file: {}
",
            dir.path().join("absent").display()
        );
        assert!(matches!(
            parse(&missing).into_run_settings(&no_env),
            Err(ConfigError::ReadFile { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_client_secret_that_is_not_unicode_is_refused() {
        use std::os::unix::ffi::OsStringExt;

        let env = |name: &str| (name == CLIENT_SECRET_VAR).then(|| OsString::from_vec(vec![0xff]));
        assert!(matches!(
            parse("").into_run_settings(&env),
            Err(ConfigError::ClientSecretNotUnicode)
        ));
    }

    #[test]
    fn errors_never_contain_the_client_secret() {
        let dir = tempfile::tempdir().unwrap();
        let path = secret_file(dir.path(), SECRET);
        let from_file = format!(
            "  client_secret_file: {}
",
            path.display()
        );
        let absent_roots = format!(
            "{from_file}  extra_root_certificates_file: {}
",
            dir.path().join("absent.pem").display()
        );
        let mut bad_ttl = parse(&from_file);
        bad_ttl.cert_ttl_secs = 1;
        let mut bad_url = parse(&from_file);
        bad_url.public_url = Some(format!("http://{SECRET}"));
        let failures = [
            parse(&from_file).into_run_settings(&secret_env).err(),
            parse(&absent_roots).into_run_settings(&no_env).err(),
            bad_ttl.into_run_settings(&no_env).err(),
            bad_url.into_run_settings(&no_env).err(),
        ];
        for failure in failures {
            let err = failure.expect("the config must be refused");
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains(SECRET), "{shown}");
        }
    }

    #[test]
    fn extra_root_certificates_are_read_from_the_named_file() {
        let dir = tempfile::tempdir().unwrap();
        let pem = dir.path().join("roots.pem");
        std::fs::write(&pem, "pem-text").unwrap();
        let extra = format!("  extra_root_certificates_file: {}\n", pem.display());
        let settings = parse(&extra).into_run_settings(&secret_env).unwrap();
        assert_eq!(settings.oidc.extra_root_certificates_pem, ["pem-text"]);
        let absent = format!(
            "  extra_root_certificates_file: {}\n",
            dir.path().join("absent.pem").display()
        );
        assert!(matches!(
            parse(&absent).into_run_settings(&secret_env),
            Err(ConfigError::ReadFile { .. })
        ));
    }
}
