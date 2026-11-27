use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use jaunt_proto::{ClientConfig, ClientTransport, GateEndpoint};

use crate::issued::canonical_host_key;
use crate::profile::ProfileName;

pub const GATE_USER: &str = "jaunt";
pub const DEFAULT_GATE_PORT: u16 = 22;
pub const HEADER: &str = "# Managed by jaunt. Do not edit.";

const MAX_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_SUFFIX_LEN: usize = MAX_DNS_NAME_LEN - MAX_LABEL_LEN - 1;
const MAX_HOST_CA_KEYS: usize = 16;
const MIN_SUFFIX_LABELS: usize = 2;
const PRIVATE_KEY_FILE: &str = "id_ed25519";
const CERTIFICATE_FILE: &str = "id_ed25519-cert.pub";
const KNOWN_HOSTS_FILE: &str = "known_hosts";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SshConfigError {
    #[error("the server sent an SSH domain suffix that is not a lowercase DNS name")]
    BadSuffix,
    #[error("the server sent a gate host that is neither a lowercase DNS name nor an IP address")]
    BadGateHost,
    #[error("the server sent a gate port that is not between 1 and 65535")]
    BadGatePort,
    #[error("the server sent no usable host CA keys")]
    BadHostKeys,
    #[error(
        "the path {path:?} contains characters that cannot be written to an ssh_config safely; \
         choose another JAUNT_HOME"
    )]
    UnsafePath { path: PathBuf },
    #[error(
        "the jaunt program path {path:?} contains characters that cannot be written to an ssh_config safely; \
         install jaunt in another directory"
    )]
    UnsafeProgram { path: PathBuf },
    #[error("the profile name {name:?} cannot be written to an ssh_config safely")]
    UnsafeProfile { name: String },
    #[error("the server sent a services domain that is not a lowercase DNS name")]
    BadServicesDomain,
    #[error("the server sent a TLS name for the gate that is not a lowercase DNS name")]
    BadGateTlsName,
    #[error("the server sent a TLS port for the gate that is not between 1 and 65535")]
    BadServicesPort,
    #[error("the server sent unusable TLS protocol names for the gate")]
    BadAlpn,
    #[error("the server offers SSH over TLS without the jaunt-ssh/1 protocol")]
    MissingSshAlpn,
    #[error("the server sent no pinned root for the gate, or more than 8")]
    RootCount,
    #[error("the server sent a pinned root that is not base64 DER")]
    RootUnreadable,
    #[error("the server sent a pinned root whose SHA-256 does not match the certificate")]
    RootDigest,
    #[error("the server sent a pinned root that is not a CA certificate")]
    RootNotCa,
    #[error("the server sent a pinned root that is not self-signed")]
    RootNotSelfSigned,
    #[error("the pinned root of the gate is not valid at this time (check the system clock)")]
    RootOutsideValidity,
}

#[derive(Debug, Clone, Copy)]
pub struct EnsureCommand<'a> {
    pub program: &'a Path,
    pub home: Option<&'a Path>,
    pub profile: &'a ProfileName,
}

pub fn validate(config: ClientConfig) -> Result<ClientConfig, SshConfigError> {
    let ClientConfig {
        ssh_suffix,
        gate,
        host_ca_keys,
    } = config;
    if ssh_suffix.len() > MAX_SUFFIX_LEN
        || !is_dns_name(&ssh_suffix)
        || ssh_suffix.split('.').count() < MIN_SUFFIX_LABELS
    {
        return Err(SshConfigError::BadSuffix);
    }
    let host = canonical_host(&gate.host)?;
    if gate.port == 0 {
        return Err(SshConfigError::BadGatePort);
    }
    if host_ca_keys.is_empty() || host_ca_keys.len() > MAX_HOST_CA_KEYS {
        return Err(SshConfigError::BadHostKeys);
    }
    let host_ca_keys = host_ca_keys
        .iter()
        .map(|line| canonical_host_key(line).ok_or(SshConfigError::BadHostKeys))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ClientConfig {
        ssh_suffix,
        gate: GateEndpoint {
            host,
            port: gate.port,
        },
        host_ca_keys,
    })
}

fn canonical_host(host: &str) -> Result<String, SshConfigError> {
    if host.contains(':') {
        return host
            .parse::<Ipv6Addr>()
            .ok()
            .filter(|addr| addr.to_string() == host)
            .map(|addr| addr.to_string())
            .ok_or(SshConfigError::BadGateHost);
    }
    if host.len() <= MAX_DNS_NAME_LEN && (host.parse::<Ipv4Addr>().is_ok() || is_dns_name(host)) {
        Ok(host.to_owned())
    } else {
        Err(SshConfigError::BadGateHost)
    }
}

pub fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_LABEL_LEN
        && edge(*first)
        && edge(*last)
        && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

pub(crate) fn is_dns_name(text: &str) -> bool {
    text.len() <= MAX_DNS_NAME_LEN && text.split('.').all(is_dns_label)
}

fn is_safe_path(text: &str) -> bool {
    text.starts_with('/')
        && text.chars().all(|ch| {
            ch.is_alphanumeric()
                || matches!(
                    ch,
                    '/' | '.' | '_' | '+' | '@' | ',' | ':' | '=' | '-' | ' '
                )
        })
}

fn is_safe_word(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

pub fn path_argument(text: &str) -> Option<String> {
    if !is_safe_path(text) {
        return None;
    }
    if text.contains(' ') {
        Some(format!("\"{text}\""))
    } else {
        Some(text.to_owned())
    }
}

fn profile_path(profile_dir: &Path, file: &str) -> Result<String, SshConfigError> {
    let unsafe_path = || SshConfigError::UnsafePath {
        path: profile_dir.join(file),
    };
    let text = profile_dir.join(file);
    let text = text.to_str().ok_or_else(unsafe_path)?;
    path_argument(text).ok_or_else(unsafe_path)
}

fn jump_target(gate: &GateEndpoint) -> String {
    if gate.host.contains(':') {
        format!("[{}]:{}", gate.host, gate.port)
    } else {
        format!("{}:{}", gate.host, gate.port)
    }
}

pub fn check_profile_dir(profile_dir: &Path) -> Result<(), SshConfigError> {
    for file in [PRIVATE_KEY_FILE, CERTIFICATE_FILE, KNOWN_HOSTS_FILE] {
        profile_path(profile_dir, file)?;
    }
    Ok(())
}

struct CommandWords<'a> {
    program: &'a str,
    profile: &'a str,
    home: String,
}

fn command_words<'a>(command: &EnsureCommand<'a>) -> Result<CommandWords<'a>, SshConfigError> {
    let program = command
        .program
        .to_str()
        .filter(|text| is_safe_path(text))
        .ok_or_else(|| SshConfigError::UnsafeProgram {
            path: command.program.to_owned(),
        })?;
    let profile = command.profile.as_str();
    if !is_safe_word(profile) {
        return Err(SshConfigError::UnsafeProfile {
            name: profile.to_owned(),
        });
    }
    let home = match command.home {
        Some(home) => {
            let text = home
                .to_str()
                .filter(|text| is_safe_path(text))
                .ok_or_else(|| SshConfigError::UnsafePath {
                    path: home.to_owned(),
                })?;
            format!(" --home '{text}'")
        }
        None => String::new(),
    };
    Ok(CommandWords {
        program,
        profile,
        home,
    })
}

fn ensure_words(command: &EnsureCommand<'_>) -> Result<String, SshConfigError> {
    let CommandWords {
        program,
        profile,
        home,
    } = command_words(command)?;
    Ok(format!(
        "'{program}' ensure{home} --profile {profile} --quiet"
    ))
}

pub fn proxy_command_line(command: &EnsureCommand<'_>) -> Result<String, SshConfigError> {
    let CommandWords {
        program,
        profile,
        home,
    } = command_words(command)?;
    Ok(format!(
        "ProxyCommand '{program}' proxy ssh --profile {profile}{home}"
    ))
}

pub fn check_ensure_command(command: &EnsureCommand<'_>) -> Result<(), SshConfigError> {
    ensure_words(command).map(drop)
}

pub fn ensure_match_line(
    ssh_suffix: &str,
    command: &EnsureCommand<'_>,
) -> Result<String, SshConfigError> {
    let words = ensure_words(command)?;
    Ok(format!("Match host *.{ssh_suffix} exec \"{words}\""))
}

pub fn render_ssh_config(
    config: &ClientConfig,
    transport: ClientTransport,
    profile_dir: &Path,
    command: &EnsureCommand<'_>,
) -> Result<String, SshConfigError> {
    let identity = profile_path(profile_dir, PRIVATE_KEY_FILE)?;
    let certificate = profile_path(profile_dir, CERTIFICATE_FILE)?;
    let known_hosts = profile_path(profile_dir, KNOWN_HOSTS_FILE)?;
    let auto_sign_in = ensure_match_line(&config.ssh_suffix, command)?;
    let route = match transport {
        ClientTransport::Tcp => "ProxyJump none".to_owned(),
        ClientTransport::Tls => proxy_command_line(command)?,
    };
    let common = format!(
        "    IdentityFile {identity}\n    CertificateFile {certificate}\n    IdentitiesOnly yes\n    UserKnownHostsFile {known_hosts}\n    StrictHostKeyChecking yes\n"
    );
    let gate = &config.gate;
    let mut text = format!(
        "{HEADER}\n{auto_sign_in}\n\nHost {}\n    User {GATE_USER}\n",
        gate.host
    );
    if gate.port != DEFAULT_GATE_PORT {
        text.push_str(&format!("    Port {}\n", gate.port));
    }
    text.push_str(&format!("    {route}\n"));
    text.push_str(&common);
    text.push_str(&format!(
        "\nHost *.{}\n    ProxyJump {GATE_USER}@{}\n",
        config.ssh_suffix,
        jump_target(gate)
    ));
    text.push_str(&common);
    Ok(text)
}

pub fn render_known_hosts(config: &ClientConfig) -> String {
    let gate = &config.gate;
    let mut patterns = vec![format!("*.{}", config.ssh_suffix), gate.host.clone()];
    if gate.port != DEFAULT_GATE_PORT {
        patterns.push(format!("[{}]:{}", gate.host, gate.port));
    }
    let mut text = String::new();
    for pattern in &patterns {
        for key in &config.host_ca_keys {
            text.push_str(&format!("@cert-authority {pattern} {key}\n"));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use jaunt_proto::{ClientConfig, ClientTransport, GateEndpoint};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, PublicKey};

    use super::{
        EnsureCommand, SshConfigError, check_ensure_command, proxy_command_line,
        render_known_hosts, validate,
    };
    use crate::profile::ProfileName;

    const PROGRAM: &str = "/usr/local/bin/jaunt";

    fn render_ssh_config(
        config: &ClientConfig,
        profile_dir: &Path,
    ) -> Result<String, SshConfigError> {
        let profile = ProfileName::default_name();
        let command = EnsureCommand {
            program: Path::new(PROGRAM),
            home: None,
            profile: &profile,
        };
        super::render_ssh_config(config, ClientTransport::Tcp, profile_dir, &command)
    }

    fn key_line() -> String {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        PublicKey::from(key.public_key().key_data().clone())
            .to_openssh()
            .unwrap()
    }

    fn config(suffix: &str, host: &str, port: u16, keys: &[String]) -> ClientConfig {
        ClientConfig {
            ssh_suffix: suffix.to_owned(),
            gate: GateEndpoint {
                host: host.to_owned(),
                port,
            },
            host_ca_keys: keys.to_vec(),
        }
    }

    #[test]
    fn the_ssh_config_for_the_default_port_matches_the_golden_text() {
        let key = key_line();
        let valid = validate(config("example.test", "gate.example.org", 22, &[key])).unwrap();

        let text = render_ssh_config(&valid, Path::new("/home/u/.jaunt/default")).unwrap();

        let expected = "# Managed by jaunt. Do not edit.
Match host *.example.test exec \"'/usr/local/bin/jaunt' ensure --profile default --quiet\"

Host gate.example.org
    User jaunt
    ProxyJump none
    IdentityFile /home/u/.jaunt/default/id_ed25519
    CertificateFile /home/u/.jaunt/default/id_ed25519-cert.pub
    IdentitiesOnly yes
    UserKnownHostsFile /home/u/.jaunt/default/known_hosts
    StrictHostKeyChecking yes

Host *.example.test
    ProxyJump jaunt@gate.example.org:22
    IdentityFile /home/u/.jaunt/default/id_ed25519
    CertificateFile /home/u/.jaunt/default/id_ed25519-cert.pub
    IdentitiesOnly yes
    UserKnownHostsFile /home/u/.jaunt/default/known_hosts
    StrictHostKeyChecking yes
";
        assert_eq!(text, expected);
    }

    #[test]
    fn a_non_default_port_and_an_ipv6_gate_are_written_with_brackets_and_a_port_line() {
        let valid = validate(config("example.test", "2001:db8::1", 2222, &[key_line()])).unwrap();

        let text = render_ssh_config(&valid, Path::new("/p")).unwrap();

        assert!(text.contains("Host 2001:db8::1\n    User jaunt\n    Port 2222\n"));
        assert!(text.contains("    ProxyJump jaunt@[2001:db8::1]:2222\n"));
        let hosts = render_known_hosts(&valid);
        assert!(hosts.contains("@cert-authority [2001:db8::1]:2222 ssh-ed25519 "));
    }

    #[test]
    fn known_hosts_has_one_line_per_key_per_pattern_and_no_comments() {
        let (first, second) = (key_line(), key_line());
        let keys = [first.clone(), second.clone()];
        let default_port = validate(config("example.test", "gate.example.org", 22, &keys)).unwrap();
        let custom_port =
            validate(config("example.test", "gate.example.org", 2222, &keys)).unwrap();

        assert_eq!(
            render_known_hosts(&default_port),
            format!(
                "@cert-authority *.example.test {first}\n@cert-authority *.example.test {second}\n@cert-authority gate.example.org {first}\n@cert-authority gate.example.org {second}\n"
            )
        );
        assert_eq!(
            render_known_hosts(&custom_port),
            format!(
                "@cert-authority *.example.test {first}\n@cert-authority *.example.test {second}\n@cert-authority gate.example.org {first}\n@cert-authority gate.example.org {second}\n@cert-authority [gate.example.org]:2222 {first}\n@cert-authority [gate.example.org]:2222 {second}\n"
            )
        );
    }

    #[test]
    fn host_keys_are_rewritten_without_their_comments() {
        let commented = format!("{} someone@laptop", key_line());

        let valid = validate(config("example.test", "gate.example.org", 22, &[commented])).unwrap();

        assert_eq!(valid.host_ca_keys[0].split(' ').count(), 2);
    }

    #[test]
    fn hostile_values_are_refused_before_anything_can_be_rendered() {
        let key = key_line();
        let long_label = "a".repeat(64);
        let long_name = format!("{0}.{0}.{0}.{0}", "a".repeat(62));
        let suffixes = [
            "",
            "com",
            "corp",
            "example.test\nProxyCommand touch /tmp/x",
            "example.test ProxyCommand=x",
            "exam ple.test",
            "example.test%h",
            "example.test;id",
            "example.test#",
            "Example.Test",
            "*.example.test",
            "exämple.test",
            "-example.test",
            ".example.test",
            "example..test",
            "example.test.",
            long_label.as_str(),
            long_name.as_str(),
        ];
        for suffix in suffixes {
            let outcome = validate(config(
                suffix,
                "gate.example.org",
                22,
                std::slice::from_ref(&key),
            ));
            assert_eq!(outcome.err(), Some(SshConfigError::BadSuffix), "{suffix:?}");
        }
        let hosts = [
            "",
            "gate.example.org\nProxyCommand x",
            "gate.example.org extra",
            "gate%h.example.org",
            "gate;id",
            "gäte.example.org",
            "Gate.example.org",
            "-oProxyCommand=x",
            "fe80::1%eth0",
            "::ffff:1.2.3.4x",
            "2001:DB8::1",
            "[::1]",
        ];
        for host in hosts {
            let outcome = validate(config("example.test", host, 22, std::slice::from_ref(&key)));
            assert_eq!(outcome.err(), Some(SshConfigError::BadGateHost), "{host:?}");
        }
        assert_eq!(
            validate(config(
                "example.test",
                "gate.example.org",
                0,
                std::slice::from_ref(&key)
            ))
            .err(),
            Some(SshConfigError::BadGatePort)
        );
        for keys in [
            vec![],
            vec![format!("{key}\nProxyCommand x")],
            vec!["not a key".to_owned()],
            vec![key.clone(); 17],
        ] {
            assert_eq!(
                validate(config("example.test", "gate.example.org", 22, &keys)).err(),
                Some(SshConfigError::BadHostKeys)
            );
        }
    }

    #[test]
    fn plain_hosts_ip_literals_and_numeric_names_are_accepted() {
        let key = key_line();
        for host in [
            "gate",
            "10.0.0.1",
            "gate-1.example.org",
            "::1",
            "2001:db8::1",
        ] {
            assert!(
                validate(config("corp.test", host, 22, std::slice::from_ref(&key))).is_ok(),
                "{host}"
            );
        }
    }

    #[test]
    fn unsafe_profile_paths_are_refused_and_spaces_are_quoted() {
        let valid = validate(config(
            "example.test",
            "gate.example.org",
            22,
            &[key_line()],
        ))
        .unwrap();
        for path in [
            "/home/u/.jaunt/def\nault",
            "/home/u/50%/default",
            "/home/u/$HOME/default",
            "/home/u/a\"b/default",
            "/home/u/a'b/default",
            "/home/u/a;b/default",
            "/home/u/a#b/default",
            "/home/u/a*b/default",
            "/home/u/a\\b/default",
            "relative/default",
        ] {
            let outcome = render_ssh_config(&valid, Path::new(path));
            assert!(
                matches!(outcome, Err(SshConfigError::UnsafePath { .. })),
                "{path:?}"
            );
        }
        let spaced = render_ssh_config(&valid, Path::new("/home/Jane Doe/.jaunt/default")).unwrap();
        assert!(spaced.contains("    IdentityFile \"/home/Jane Doe/.jaunt/default/id_ed25519\"\n"));
        let accented = render_ssh_config(&valid, Path::new("/home/jörg/.jaunt/default")).unwrap();
        assert!(accented.contains("    IdentityFile /home/jörg/.jaunt/default/id_ed25519\n"));
    }

    #[test]
    fn the_auto_sign_in_block_for_a_spaced_accented_home_matches_the_golden_text() {
        let valid = validate(config("corp.test", "gate.corp.test", 22, &[key_line()])).unwrap();
        let profile = ProfileName::parse("work-2").unwrap();
        let command = EnsureCommand {
            program: Path::new("/home/Jörg Müller/bin/jaunt"),
            home: Some(Path::new("/srv/Jörg Müller/jaunt")),
            profile: &profile,
        };

        let text = super::render_ssh_config(
            &valid,
            ClientTransport::Tcp,
            Path::new("/srv/Jörg Müller/jaunt/work-2"),
            &command,
        )
        .unwrap();

        let expected = "# Managed by jaunt. Do not edit.
Match host *.corp.test exec \"'/home/Jörg Müller/bin/jaunt' ensure --home '/srv/Jörg Müller/jaunt' --profile work-2 --quiet\"

Host gate.corp.test
    User jaunt
    ProxyJump none
    IdentityFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519\"
    CertificateFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519-cert.pub\"
    IdentitiesOnly yes
    UserKnownHostsFile \"/srv/Jörg Müller/jaunt/work-2/known_hosts\"
    StrictHostKeyChecking yes

Host *.corp.test
    ProxyJump jaunt@gate.corp.test:22
    IdentityFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519\"
    CertificateFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519-cert.pub\"
    IdentitiesOnly yes
    UserKnownHostsFile \"/srv/Jörg Müller/jaunt/work-2/known_hosts\"
    StrictHostKeyChecking yes
";
        assert_eq!(text, expected);
        assert!(!text.contains('%'));
    }

    #[test]
    fn the_tls_transport_gives_the_gate_a_proxy_command_and_keeps_the_jump_for_nodes() {
        let valid = validate(config("corp.test", "gate.corp.test", 2222, &[key_line()])).unwrap();
        let profile = ProfileName::parse("work-2").unwrap();
        let command = EnsureCommand {
            program: Path::new("/home/Jörg Müller/bin/jaunt"),
            home: Some(Path::new("/srv/Jörg Müller/jaunt")),
            profile: &profile,
        };

        let text = super::render_ssh_config(
            &valid,
            ClientTransport::Tls,
            Path::new("/srv/Jörg Müller/jaunt/work-2"),
            &command,
        )
        .unwrap();
        let again = super::render_ssh_config(
            &valid,
            ClientTransport::Tls,
            Path::new("/srv/Jörg Müller/jaunt/work-2"),
            &command,
        )
        .unwrap();

        let expected = "# Managed by jaunt. Do not edit.
Match host *.corp.test exec \"'/home/Jörg Müller/bin/jaunt' ensure --home '/srv/Jörg Müller/jaunt' --profile work-2 --quiet\"

Host gate.corp.test
    User jaunt
    Port 2222
    ProxyCommand '/home/Jörg Müller/bin/jaunt' proxy ssh --profile work-2 --home '/srv/Jörg Müller/jaunt'
    IdentityFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519\"
    CertificateFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519-cert.pub\"
    IdentitiesOnly yes
    UserKnownHostsFile \"/srv/Jörg Müller/jaunt/work-2/known_hosts\"
    StrictHostKeyChecking yes

Host *.corp.test
    ProxyJump jaunt@gate.corp.test:2222
    IdentityFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519\"
    CertificateFile \"/srv/Jörg Müller/jaunt/work-2/id_ed25519-cert.pub\"
    IdentitiesOnly yes
    UserKnownHostsFile \"/srv/Jörg Müller/jaunt/work-2/known_hosts\"
    StrictHostKeyChecking yes
";
        assert_eq!(text, expected);
        assert_eq!(again, text);
        let default_home = EnsureCommand {
            program: Path::new(PROGRAM),
            home: None,
            profile: &profile,
        };
        assert_eq!(
            proxy_command_line(&default_home).unwrap(),
            "ProxyCommand '/usr/local/bin/jaunt' proxy ssh --profile work-2"
        );
    }

    #[test]
    fn a_program_path_that_a_shell_could_misread_is_refused_before_any_text_exists() {
        let valid = validate(config(
            "example.test",
            "gate.example.org",
            22,
            &[key_line()],
        ))
        .unwrap();
        let profile = ProfileName::default_name();
        for program in [
            "/opt/ja'unt/jaunt",
            "/opt/ja\"unt/jaunt",
            "/opt/$HOME/jaunt",
            "/opt/50%h/jaunt",
            "/opt/a;b/jaunt",
            "/opt/a`id`/jaunt",
            "/opt/a\\b/jaunt",
            "/opt/a\nb/jaunt",
            "/opt/a*b/jaunt",
            "/opt/~/jaunt",
            "relative/jaunt",
        ] {
            let command = EnsureCommand {
                program: Path::new(program),
                home: None,
                profile: &profile,
            };
            let outcome =
                super::render_ssh_config(&valid, ClientTransport::Tcp, Path::new("/p"), &command);
            assert!(
                matches!(outcome, Err(SshConfigError::UnsafeProgram { .. })),
                "{program:?}"
            );
            assert!(check_ensure_command(&command).is_err(), "{program:?}");
            let outcome =
                super::render_ssh_config(&valid, ClientTransport::Tls, Path::new("/p"), &command);
            assert!(
                matches!(outcome, Err(SshConfigError::UnsafeProgram { .. })),
                "{program:?}"
            );
        }
        for home in ["/srv/50%", "/srv/a'b", "/srv/$X", "relative"] {
            let command = EnsureCommand {
                program: Path::new(PROGRAM),
                home: Some(Path::new(home)),
                profile: &profile,
            };
            assert!(
                matches!(
                    check_ensure_command(&command),
                    Err(SshConfigError::UnsafePath { .. })
                ),
                "{home:?}"
            );
        }
    }
}
