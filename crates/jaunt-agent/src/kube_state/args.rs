use std::path::PathBuf;

use clap::Args;

use super::client::ClusterSettings;
use super::mount::is_dns_subdomain;
use super::persist::PersistTiming;
use super::{EnrollPlan, KubernetesBackend, StateBackend, TOKEN_ATTEMPTS, TOKEN_RETRY_EVERY};
use crate::enroll::args::{Labels, ServerUrl, parse_name};
use crate::pin::CaPin;
use crate::run::config::{AgentConfig, BackendKind};

pub const DEFAULT_SECRET_NAME: &str = "jaunt-agent-state";
pub const DEFAULT_JOIN_TOKEN_FILE: &str = "/var/run/secrets/jaunt/join-token";

#[derive(Debug, Default, Args)]
pub struct ClusterArgs {
    #[arg(
        long,
        value_name = "BACKEND",
        help = "Where the durable copy of the node identity lives: file (the state directory, default) or kubernetes (a Secret of the pod's namespace)"
    )]
    pub state_backend: Option<BackendKind>,
    #[arg(
        long,
        value_name = "URL",
        help = "kubernetes backend: the server to enrol with when the Secret holds no enrollment"
    )]
    pub server: Option<ServerUrl>,
    #[arg(
        long,
        value_name = "NAME",
        value_parser = parse_name,
        help = "kubernetes backend: the node name to enrol, kube-<cluster>"
    )]
    pub name: Option<String>,
    #[arg(
        long,
        value_name = "K=V,...",
        help = "kubernetes backend: node labels to enrol with"
    )]
    pub labels: Option<Labels>,
    #[arg(
        long,
        value_name = "sha256:HEX",
        help = "kubernetes backend (required): the pin of the server's internal CA root, checked at enrollment and at every restore"
    )]
    pub ca_pin: Option<CaPin>,
    #[arg(
        long,
        value_name = "PATH",
        help = "kubernetes backend: the mounted join token (default /var/run/secrets/jaunt/join-token)"
    )]
    pub join_token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectError {
    #[error(
        "--state-backend {flag} contradicts state.backend: {config} in the agent configuration"
    )]
    Conflict {
        flag: BackendKind,
        config: BackendKind,
    },
    #[error(
        "{0} is accepted only with the kubernetes state backend; on a host, enrol with `jaunt-agent enroll`"
    )]
    FileBackend(&'static str),
    #[error("the kubernetes state backend needs {0}")]
    Missing(&'static str),
    #[error(
        "the kubernetes state backend needs --ca-pin: the pin of the server's CA is required, because without it whoever can update the Secret controls the agent; `jauntd ca init` printed it as the internal-ca line, and it can be computed again on the server with `sha256sum <data_dir>/ca/internal/*.root.der` (see Internal CA pin in docs/operations.md)"
    )]
    PinRequired,
    #[error(
        "the kubernetes state backend needs ssh.enabled: false in the agent configuration: a pod has no sshd"
    )]
    SshEnabled,
    #[error(
        "the kubernetes state backend needs host_users.enabled: false in the agent configuration: a pod has no host accounts to create"
    )]
    HostUsers,
    #[error(
        "state.secret_name must be a DNS subdomain name: lowercase letters, digits, - and ., at most 253 characters"
    )]
    SecretName,
}

pub fn select(args: &ClusterArgs, config: &AgentConfig) -> Result<StateBackend, SelectError> {
    let kind = match (args.state_backend, config.state.backend) {
        (Some(flag), Some(config)) if flag != config => {
            return Err(SelectError::Conflict { flag, config });
        }
        (flag, config) => flag.or(config).unwrap_or_default(),
    };
    match kind {
        BackendKind::File => {
            let kubernetes_only = [
                (args.server.is_some(), "--server"),
                (args.name.is_some(), "--name"),
                (args.labels.is_some(), "--labels"),
                (args.ca_pin.is_some(), "--ca-pin"),
                (args.join_token_file.is_some(), "--join-token-file"),
                (config.state.secret_name.is_some(), "state.secret_name"),
            ];
            match kubernetes_only.into_iter().find(|(set, _)| *set) {
                Some((_, flag)) => Err(SelectError::FileBackend(flag)),
                None => Ok(StateBackend::File),
            }
        }
        BackendKind::Kubernetes => {
            let server = args
                .server
                .clone()
                .ok_or(SelectError::Missing("--server"))?;
            let name = args.name.clone().ok_or(SelectError::Missing("--name"))?;
            let ca_pin = args.ca_pin.clone().ok_or(SelectError::PinRequired)?;
            if config.ssh.enabled {
                return Err(SelectError::SshEnabled);
            }
            if config.host_users.enabled {
                return Err(SelectError::HostUsers);
            }
            let secret_name = config
                .state
                .secret_name
                .clone()
                .unwrap_or_else(|| DEFAULT_SECRET_NAME.to_owned());
            if !is_dns_subdomain(&secret_name) {
                return Err(SelectError::SecretName);
            }
            Ok(StateBackend::Kubernetes(Box::new(KubernetesBackend {
                cluster: ClusterSettings::in_cluster(secret_name),
                enrollment: EnrollPlan {
                    server,
                    name,
                    labels: args.labels.clone().unwrap_or_default().into_map(),
                    ca_pin,
                    token_file: args
                        .join_token_file
                        .clone()
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_JOIN_TOKEN_FILE)),
                    token_attempts: TOKEN_ATTEMPTS,
                    token_retry_every: TOKEN_RETRY_EVERY,
                    hostname: None,
                },
                timing: PersistTiming::default(),
            })))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use clap::Parser;

    use super::{ClusterArgs, SelectError, select};
    use crate::kube_state::StateBackend;
    use crate::run::config::{AgentConfig, BackendKind, SshConfig, StateConfig};

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: ClusterArgs,
    }

    fn args(line: &[&str]) -> ClusterArgs {
        let mut words = vec!["run"];
        words.extend_from_slice(line);
        Cli::try_parse_from(words).unwrap().args
    }

    fn pod_config() -> AgentConfig {
        AgentConfig {
            ssh: SshConfig { enabled: false },
            ..AgentConfig::default()
        }
    }

    fn with_state(
        mut config: AgentConfig,
        backend: Option<BackendKind>,
        secret: Option<&str>,
    ) -> AgentConfig {
        config.state = StateConfig {
            backend,
            secret_name: secret.map(str::to_owned),
        };
        config
    }

    const PIN: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const POD: [&str; 8] = [
        "--state-backend",
        "kubernetes",
        "--server",
        "https://jaunt.example.com",
        "--name",
        "kube-prod",
        "--ca-pin",
        PIN,
    ];

    #[test]
    fn the_kubernetes_backend_takes_its_defaults_from_the_pod_layout() {
        let StateBackend::Kubernetes(backend) = select(&args(&POD), &pod_config()).unwrap() else {
            panic!("expected the kubernetes backend");
        };
        assert_eq!(backend.cluster.timeout, Duration::from_secs(10));
        assert_eq!(backend.enrollment.ca_pin, PIN.parse().unwrap());
        assert_eq!(backend.enrollment.token_attempts, 10);
        assert_eq!(backend.enrollment.token_retry_every, Duration::from_secs(1));
        assert_eq!(
            backend.cluster.service_account_dir,
            Path::new("/var/run/secrets/kubernetes.io/serviceaccount")
        );
        assert_eq!(backend.cluster.secret_name, "jaunt-agent-state");
        assert_eq!(
            backend.enrollment.token_file,
            Path::new("/var/run/secrets/jaunt/join-token")
        );
        assert_eq!(backend.enrollment.name, "kube-prod");
        assert!(backend.enrollment.labels.is_empty());

        let from_config = with_state(
            pod_config(),
            Some(BackendKind::Kubernetes),
            Some("agent.state"),
        );
        let StateBackend::Kubernetes(backend) = select(&args(&POD[2..]), &from_config).unwrap()
        else {
            panic!("expected the kubernetes backend");
        };
        assert_eq!(backend.cluster.secret_name, "agent.state");
        assert!(matches!(
            select(&args(&[]), &AgentConfig::default()).unwrap(),
            StateBackend::File
        ));
        assert!(matches!(
            select(
                &args(&["--state-backend", "file"]),
                &with_state(AgentConfig::default(), Some(BackendKind::File), None)
            )
            .unwrap(),
            StateBackend::File
        ));
    }

    #[test]
    fn every_other_combination_is_refused_with_its_reason() {
        let kube = |config: AgentConfig| (POD.to_vec(), config);
        let cases: Vec<((Vec<&str>, AgentConfig), SelectError)> = vec![
            (
                (
                    vec!["--state-backend", "file"],
                    with_state(pod_config(), Some(BackendKind::Kubernetes), None),
                ),
                SelectError::Conflict {
                    flag: BackendKind::File,
                    config: BackendKind::Kubernetes,
                },
            ),
            (
                (
                    vec!["--server", "https://jaunt.example.com"],
                    AgentConfig::default(),
                ),
                SelectError::FileBackend("--server"),
            ),
            (
                (vec!["--name", "kube-prod"], AgentConfig::default()),
                SelectError::FileBackend("--name"),
            ),
            (
                (vec!["--labels", "env=prod"], AgentConfig::default()),
                SelectError::FileBackend("--labels"),
            ),
            (
                (vec!["--ca-pin", PIN], AgentConfig::default()),
                SelectError::FileBackend("--ca-pin"),
            ),
            (
                (vec!["--join-token-file", "/t"], AgentConfig::default()),
                SelectError::FileBackend("--join-token-file"),
            ),
            (
                (vec![], with_state(AgentConfig::default(), None, Some("s"))),
                SelectError::FileBackend("state.secret_name"),
            ),
            (
                (POD[..4].to_vec(), pod_config()),
                SelectError::Missing("--name"),
            ),
            (
                (
                    vec!["--state-backend", "kubernetes", "--name", "kube-prod"],
                    pod_config(),
                ),
                SelectError::Missing("--server"),
            ),
            ((POD[..6].to_vec(), pod_config()), SelectError::PinRequired),
            (kube(AgentConfig::default()), SelectError::SshEnabled),
            (
                kube(AgentConfig {
                    host_users: jaunt_host_users::HostUsersSection {
                        enabled: true,
                        ..Default::default()
                    },
                    ..pod_config()
                }),
                SelectError::HostUsers,
            ),
            (
                kube(with_state(pod_config(), None, Some("Bad_Name"))),
                SelectError::SecretName,
            ),
            (
                kube(with_state(pod_config(), None, Some("../../secrets/other"))),
                SelectError::SecretName,
            ),
        ];
        for ((line, config), expected) in cases {
            let error = select(&args(&line), &config).err();
            assert_eq!(error.as_ref(), Some(&expected), "{line:?}");
        }
        let refusal = select(&args(&POD[..6]), &pod_config())
            .err()
            .unwrap()
            .to_string();
        assert!(refusal.contains("whoever can update the Secret controls the agent"));
        assert!(refusal.contains("sha256sum"));
        assert!(Cli::try_parse_from(["run", "--state-backend", "s3"]).is_err());
        assert!(Cli::try_parse_from(["run", "--name", "Kube_Prod"]).is_err());
    }
}
