use jaunt_control::{MAX_CONNECTIONS_LIMIT, RequestLimits};
use jaunt_gate::{
    DEFAULT_AGENT_CLIENT_LIMITS, DEFAULT_KUBE_CLIENT_LIMITS, DEFAULT_SSH_CLIENT_LIMITS,
};
use jaunt_limits::{
    AddressLimits, MAX_CONCURRENT_PER_ADDRESS, MAX_TRACKED_ADDRESSES, Rate, RateError,
};
use serde::Deserialize;

#[derive(Deserialize, Clone, Copy)]
#[serde(deny_unknown_fields)]
pub struct RateSection {
    pub burst: u32,
    pub per_minute: u32,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub tracked_addresses: Option<usize>,
    #[serde(default)]
    pub http: HttpLimitsSection,
    #[serde(default)]
    pub ssh: SshLimitsSection,
    #[serde(default)]
    pub agents: AgentLimitsSection,
    #[serde(default)]
    pub kube: KubeLimitsSection,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HttpLimitsSection {
    pub login_start: Option<RateSection>,
    pub login_finish: Option<RateSection>,
    pub device_start: Option<RateSection>,
    pub device_poll: Option<RateSection>,
    pub web_login: Option<RateSection>,
    pub enroll: Option<RateSection>,
    pub enroll_poll: Option<RateSection>,
    pub enrolment_lookup: Option<RateSection>,
    pub web_terminal: Option<RateSection>,
    pub other: Option<RateSection>,
    pub max_connections: Option<usize>,
    pub max_connections_per_address: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SshLimitsSection {
    pub connections: Option<RateSection>,
    pub unauthenticated_per_address: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentLimitsSection {
    pub handshakes: Option<RateSection>,
    pub handshaking_per_address: Option<usize>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct KubeLimitsSection {
    pub handshakes: Option<RateSection>,
    pub handshaking_per_address: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitSettings {
    pub http: RequestLimits,
    pub ssh: AddressLimits,
    pub agents: AddressLimits,
    pub kube: AddressLimits,
}

impl Default for LimitSettings {
    fn default() -> Self {
        Self {
            http: RequestLimits::default(),
            ssh: DEFAULT_SSH_CLIENT_LIMITS,
            agents: DEFAULT_AGENT_CLIENT_LIMITS,
            kube: DEFAULT_KUBE_CLIENT_LIMITS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    #[error("limits.{field}: {source}")]
    Rate {
        field: &'static str,
        #[source]
        source: RateError,
    },
    #[error("limits.tracked_addresses must be between 1 and {MAX_TRACKED_ADDRESSES}")]
    TrackedAddresses,
    #[error("limits.http.max_connections must be between 1 and {MAX_CONNECTIONS_LIMIT}")]
    MaxConnections,
    #[error(
        "limits.http.max_connections_per_address must be between 1 and {MAX_CONNECTIONS_LIMIT}"
    )]
    MaxConnectionsPerAddress,
    #[error("limits.{0} must be between 1 and {MAX_CONCURRENT_PER_ADDRESS}")]
    PerAddress(&'static str),
}

fn rate(
    field: &'static str,
    section: Option<RateSection>,
    default: Rate,
) -> Result<Rate, LimitsError> {
    match section {
        Some(given) => Rate::new(given.burst, given.per_minute)
            .map_err(|source| LimitsError::Rate { field, source }),
        None => Ok(default),
    }
}

fn bounded(
    value: Option<usize>,
    default: usize,
    max: usize,
    error: LimitsError,
) -> Result<usize, LimitsError> {
    let value = value.unwrap_or(default);
    if (1..=max).contains(&value) {
        Ok(value)
    } else {
        Err(error)
    }
}

impl LimitsSection {
    pub fn into_settings(self) -> Result<LimitSettings, LimitsError> {
        let defaults = LimitSettings::default();
        let tracked = bounded(
            self.tracked_addresses,
            defaults.http.tracked_addresses,
            MAX_TRACKED_ADDRESSES,
            LimitsError::TrackedAddresses,
        )?;
        let http = self.http;
        let base = defaults.http;
        let http = RequestLimits {
            login_start: rate("http.login_start", http.login_start, base.login_start)?,
            login_finish: rate("http.login_finish", http.login_finish, base.login_finish)?,
            device_start: rate("http.device_start", http.device_start, base.device_start)?,
            device_poll: rate("http.device_poll", http.device_poll, base.device_poll)?,
            web_login: rate("http.web_login", http.web_login, base.web_login)?,
            enroll: rate("http.enroll", http.enroll, base.enroll)?,
            enroll_poll: rate("http.enroll_poll", http.enroll_poll, base.enroll_poll)?,
            enrolment_lookup: rate(
                "http.enrolment_lookup",
                http.enrolment_lookup,
                base.enrolment_lookup,
            )?,
            web_terminal: rate("http.web_terminal", http.web_terminal, base.web_terminal)?,
            other: rate("http.other", http.other, base.other)?,
            tracked_addresses: tracked,
            max_connections: bounded(
                http.max_connections,
                base.max_connections,
                MAX_CONNECTIONS_LIMIT,
                LimitsError::MaxConnections,
            )?,
            max_connections_per_address: bounded(
                http.max_connections_per_address,
                base.max_connections_per_address,
                MAX_CONNECTIONS_LIMIT,
                LimitsError::MaxConnectionsPerAddress,
            )?,
        };
        let ssh = AddressLimits {
            rate: rate("ssh.connections", self.ssh.connections, defaults.ssh.rate)?,
            concurrent: bounded(
                self.ssh.unauthenticated_per_address,
                defaults.ssh.concurrent,
                MAX_CONCURRENT_PER_ADDRESS,
                LimitsError::PerAddress("ssh.unauthenticated_per_address"),
            )?,
            tracked,
        };
        let agents = AddressLimits {
            rate: rate(
                "agents.handshakes",
                self.agents.handshakes,
                defaults.agents.rate,
            )?,
            concurrent: bounded(
                self.agents.handshaking_per_address,
                defaults.agents.concurrent,
                MAX_CONCURRENT_PER_ADDRESS,
                LimitsError::PerAddress("agents.handshaking_per_address"),
            )?,
            tracked,
        };
        let kube = AddressLimits {
            rate: rate("kube.handshakes", self.kube.handshakes, defaults.kube.rate)?,
            concurrent: bounded(
                self.kube.handshaking_per_address,
                defaults.kube.concurrent,
                MAX_CONCURRENT_PER_ADDRESS,
                LimitsError::PerAddress("kube.handshaking_per_address"),
            )?,
            tracked,
        };
        Ok(LimitSettings {
            http,
            ssh,
            agents,
            kube,
        })
    }
}

#[cfg(test)]
mod tests {
    use jaunt_limits::{Rate, RateError};

    use super::{LimitSettings, LimitsError, LimitsSection};

    fn settings(text: &str) -> Result<LimitSettings, LimitsError> {
        serde_saphyr::from_str::<LimitsSection>(text)
            .unwrap()
            .into_settings()
    }

    #[test]
    fn the_defaults_are_the_documented_limits() {
        let defaults = settings("{}\n").unwrap();
        assert_eq!(defaults, LimitSettings::default());
        let http = defaults.http;
        for (rate, burst, per_minute) in [
            (http.login_start, 60, 30),
            (http.login_finish, 60, 30),
            (http.device_start, 30, 10),
            (http.device_poll, 60, 60),
            (http.web_login, 60, 30),
            (http.enroll, 60, 6),
            (http.enroll_poll, 120, 120),
            (http.enrolment_lookup, 30, 10),
            (http.web_terminal, 30, 30),
            (http.other, 600, 300),
            (defaults.ssh.rate, 600, 600),
            (defaults.agents.rate, 128, 1200),
            (defaults.kube.rate, 600, 600),
        ] {
            assert_eq!(rate, Rate::new(burst, per_minute).unwrap());
        }
        assert_eq!(http.max_connections, 4096);
        assert_eq!(http.max_connections_per_address, 256);
        assert_eq!(http.tracked_addresses, 65_536);
        assert_eq!(defaults.ssh.concurrent, 128);
        assert_eq!(defaults.agents.concurrent, 64);
        assert_eq!(defaults.kube.concurrent, 128);
        assert_eq!(defaults.kube.tracked, 65_536);
        assert_eq!(defaults.ssh.tracked, 65_536);
    }

    #[test]
    fn every_limit_can_be_tuned() {
        let tuned = settings(
            "tracked_addresses: 1000\n\
             http:\n  login_start: { burst: 5, per_minute: 2 }\n  enroll: { burst: 1, per_minute: 1 }\n  \
             enrolment_lookup: { burst: 2, per_minute: 3 }\n  \
             web_terminal: { burst: 4, per_minute: 5 }\n  \
             max_connections: 10\n  max_connections_per_address: 2\n  other: { burst: 3, per_minute: 4 }\n\
             ssh:\n  connections: { burst: 7, per_minute: 70 }\n  unauthenticated_per_address: 3\n\
             agents:\n  handshakes: { burst: 9, per_minute: 90 }\n  handshaking_per_address: 4\n\
             kube:\n  handshakes: { burst: 11, per_minute: 110 }\n  handshaking_per_address: 5\n",
        )
        .unwrap();
        assert_eq!(tuned.http.login_start, Rate::new(5, 2).unwrap());
        assert_eq!(tuned.http.enroll, Rate::new(1, 1).unwrap());
        assert_eq!(tuned.http.enrolment_lookup, Rate::new(2, 3).unwrap());
        assert_eq!(tuned.http.web_terminal, Rate::new(4, 5).unwrap());
        assert_eq!(
            tuned.http.device_poll,
            LimitSettings::default().http.device_poll
        );
        assert_eq!(tuned.http.max_connections, 10);
        assert_eq!(tuned.http.max_connections_per_address, 2);
        assert_eq!(tuned.http.other, Rate::new(3, 4).unwrap());
        assert_eq!(tuned.http.tracked_addresses, 1000);
        assert_eq!(tuned.ssh.rate, Rate::new(7, 70).unwrap());
        assert_eq!(tuned.ssh.concurrent, 3);
        assert_eq!(tuned.ssh.tracked, 1000);
        assert_eq!(tuned.agents.rate, Rate::new(9, 90).unwrap());
        assert_eq!(tuned.agents.concurrent, 4);
        assert_eq!(tuned.agents.tracked, 1000);
        assert_eq!(tuned.kube.rate, Rate::new(11, 110).unwrap());
        assert_eq!(tuned.kube.concurrent, 5);
        assert_eq!(tuned.kube.tracked, 1000);
    }

    #[test]
    fn unknown_fields_and_half_rates_are_refused_while_parsing() {
        for text in [
            "extra: 1\n",
            "http:\n  login: { burst: 1, per_minute: 1 }\n",
            "http:\n  login_start: { burst: 1 }\n",
            "http:\n  login_start: { burst: 1, per_minute: 1, per_second: 1 }\n",
            "ssh:\n  connections: { burst: -1, per_minute: 1 }\n",
            "agents:\n  handshakes_per_address: 1\n",
            "kube:\n  connections: { burst: 1, per_minute: 1 }\n",
            "ssh:\n  unauthenticated: 1\n",
            "ssh:\n  connections: { burst: 1, per_minute: 1 }\n  extra: true\n",
            "http:\n  max_connections_per_ip: 1\n",
        ] {
            assert!(
                serde_saphyr::from_str::<LimitsSection>(text).is_err(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn values_outside_their_range_are_refused_with_the_field_name() {
        for (text, expected) in [
            (
                "http:\n  enroll: { burst: 0, per_minute: 1 }\n",
                LimitsError::Rate {
                    field: "http.enroll",
                    source: RateError::Burst,
                },
            ),
            (
                "ssh:\n  connections: { burst: 1, per_minute: 0 }\n",
                LimitsError::Rate {
                    field: "ssh.connections",
                    source: RateError::PerMinute,
                },
            ),
            (
                "agents:\n  handshakes: { burst: 1, per_minute: 6000001 }\n",
                LimitsError::Rate {
                    field: "agents.handshakes",
                    source: RateError::PerMinute,
                },
            ),
            ("tracked_addresses: 0\n", LimitsError::TrackedAddresses),
            (
                "tracked_addresses: 4194305\n",
                LimitsError::TrackedAddresses,
            ),
            ("http:\n  max_connections: 0\n", LimitsError::MaxConnections),
            (
                "http:\n  max_connections_per_address: 0\n",
                LimitsError::MaxConnectionsPerAddress,
            ),
            (
                "ssh:\n  unauthenticated_per_address: 0\n",
                LimitsError::PerAddress("ssh.unauthenticated_per_address"),
            ),
            (
                "agents:\n  handshaking_per_address: 0\n",
                LimitsError::PerAddress("agents.handshaking_per_address"),
            ),
            (
                "kube:\n  handshakes: { burst: 0, per_minute: 1 }\n",
                LimitsError::Rate {
                    field: "kube.handshakes",
                    source: RateError::Burst,
                },
            ),
            (
                "kube:\n  handshaking_per_address: 1048577\n",
                LimitsError::PerAddress("kube.handshaking_per_address"),
            ),
        ] {
            let refused = settings(text).unwrap_err();
            assert_eq!(refused, expected, "{text:?}");
            assert!(refused.to_string().starts_with("limits."), "{refused}");
        }
    }
}
