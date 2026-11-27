use std::collections::HashSet;
use std::net::IpAddr;

use thiserror::Error;

use crate::ssh::{is_dns_label, normalize_dns_name};

const KUBE_LABEL: &str = "kube";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniClass {
    Agents,
    Gate,
    Kube(String),
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EntryNamesError {
    #[error("the services domain must be a dns name such as svc.example.com")]
    InvalidDomain,
    #[error("the agents' server name {0:?} falls under the services domain")]
    AgentNameCollision(String),
}

#[derive(Debug, Clone)]
pub struct EntryNames {
    agents: HashSet<String>,
    services: Option<Services>,
}

#[derive(Debug, Clone)]
struct Services {
    domain: String,
    kube_suffix: String,
}

impl EntryNames {
    pub fn new(agent_names: &[String], domain: Option<&str>) -> Result<Self, EntryNamesError> {
        let services = match domain {
            None => None,
            Some(given) => {
                let domain = service_name(given).ok_or(EntryNamesError::InvalidDomain)?;
                Some(Services {
                    kube_suffix: format!(".{KUBE_LABEL}.{domain}"),
                    domain,
                })
            }
        };
        let names = Self {
            agents: agent_names.iter().map(|name| agent_key(name)).collect(),
            services,
        };
        if let Some(collision) = agent_names
            .iter()
            .find(|name| names.classify_service(&agent_key(name)) != SniClass::Unknown)
        {
            return Err(EntryNamesError::AgentNameCollision(collision.clone()));
        }
        Ok(names)
    }

    pub fn domain(&self) -> Option<&str> {
        self.services
            .as_ref()
            .map(|services| services.domain.as_str())
    }

    pub fn classify(&self, server_name: Option<&str>) -> SniClass {
        let Some(name) = server_name else {
            return SniClass::Missing;
        };
        if self.agents.contains(&agent_key(name)) {
            return SniClass::Agents;
        }
        self.classify_service(name)
    }

    fn classify_service(&self, given: &str) -> SniClass {
        let (Some(services), Some(name)) = (&self.services, service_name(given)) else {
            return SniClass::Unknown;
        };
        if name == services.domain {
            return SniClass::Gate;
        }
        match name.strip_suffix(services.kube_suffix.as_str()) {
            Some(cluster) if is_dns_label(cluster) => SniClass::Kube(cluster.to_owned()),
            _ => SniClass::Unknown,
        }
    }
}

fn agent_key(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn service_name(given: &str) -> Option<String> {
    normalize_dns_name(given).filter(|name| name.parse::<IpAddr>().is_err())
}

#[cfg(test)]
mod tests {
    use super::{EntryNames, EntryNamesError, SniClass};

    const DOMAIN: &str = "svc.example.com";
    const AGENTS: &str = "agents.example.com";

    fn names(domain: Option<&str>) -> EntryNames {
        EntryNames::new(&[AGENTS.to_owned()], domain).unwrap()
    }

    #[test]
    fn server_names_fall_into_exactly_one_class_by_label_rules() {
        let kube = |cluster: &str| SniClass::Kube(cluster.to_owned());
        let long_label = "c".repeat(63);
        let too_long_label = "c".repeat(64);
        let cases: Vec<(Option<String>, SniClass)> = vec![
            (None, SniClass::Missing),
            (Some(AGENTS.into()), SniClass::Agents),
            (Some("AGENTS.Example.COM.".into()), SniClass::Agents),
            (Some(DOMAIN.into()), SniClass::Gate),
            (Some("SVC.Example.Com".into()), SniClass::Gate),
            (Some(format!("{DOMAIN}.")), SniClass::Gate),
            (Some(format!("{DOMAIN}..")), SniClass::Unknown),
            (Some(format!("prod-eu.kube.{DOMAIN}")), kube("prod-eu")),
            (Some(format!("Prod-EU.KUBE.{DOMAIN}.")), kube("prod-eu")),
            (
                Some(format!("{long_label}.kube.{DOMAIN}")),
                kube(&long_label),
            ),
            (
                Some(format!("{too_long_label}.kube.{DOMAIN}")),
                SniClass::Unknown,
            ),
            (Some(format!("kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!(".kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("a.b.kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("evilkube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("x.evilkube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("x.kube.evil{DOMAIN}")), SniClass::Unknown),
            (Some(format!("x.kube{DOMAIN}")), SniClass::Unknown),
            (Some(format!("evil{DOMAIN}")), SniClass::Unknown),
            (Some(format!("{DOMAIN}.evil")), SniClass::Unknown),
            (Some(format!("x.kube.{DOMAIN}.evil")), SniClass::Unknown),
            (Some(format!("agents.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("-x.kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("x_y.kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("*.kube.{DOMAIN}")), SniClass::Unknown),
            (Some(format!("ä.kube.{DOMAIN}")), SniClass::Unknown),
            (Some("svc.exämple.com".into()), SniClass::Unknown),
            (Some("192.0.2.7".into()), SniClass::Unknown),
            (Some("[2001:db8::1]".into()), SniClass::Unknown),
            (Some(String::new()), SniClass::Unknown),
            (Some("example.com".into()), SniClass::Unknown),
        ];
        let names = names(Some(DOMAIN));
        for (given, expected) in cases {
            assert_eq!(names.classify(given.as_deref()), expected, "{given:?}");
        }
    }

    #[test]
    fn a_server_name_longer_than_253_bytes_is_unknown() {
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(54)
        );
        let names = EntryNames::new(&[], Some(&domain)).unwrap();
        let fits = format!("x.kube.{domain}");
        assert_eq!(fits.len(), 253);
        assert_eq!(names.classify(Some(&fits)), SniClass::Kube("x".into()));
        assert_eq!(
            names.classify(Some(&format!("{fits}."))),
            SniClass::Kube("x".into())
        );
        assert_eq!(
            names.classify(Some(&format!("xy.kube.{domain}"))),
            SniClass::Unknown
        );
    }

    #[test]
    fn without_a_services_domain_only_the_agents_class_exists() {
        let names = names(None);
        assert_eq!(names.domain(), None);
        assert_eq!(names.classify(Some(AGENTS)), SniClass::Agents);
        assert_eq!(names.classify(Some(DOMAIN)), SniClass::Unknown);
        assert_eq!(
            names.classify(Some(&format!("prod.kube.{DOMAIN}"))),
            SniClass::Unknown
        );
        assert_eq!(names.classify(None), SniClass::Missing);
    }

    #[test]
    fn the_services_domain_is_a_dns_name_that_leaves_the_agents_alone() {
        assert_eq!(
            EntryNames::new(&[], Some("Svc.Example.com."))
                .unwrap()
                .domain(),
            Some(DOMAIN)
        );
        for invalid in ["", "*.example.com", "svc example.com", "192.0.2.7", "a..b"] {
            assert_eq!(
                EntryNames::new(&[], Some(invalid)).unwrap_err(),
                EntryNamesError::InvalidDomain,
                "{invalid:?}"
            );
        }
        for agents in [
            DOMAIN.to_owned(),
            "SVC.example.com..".to_owned(),
            format!("a1.kube.{DOMAIN}"),
        ] {
            assert_eq!(
                EntryNames::new(std::slice::from_ref(&agents), Some(DOMAIN)).unwrap_err(),
                EntryNamesError::AgentNameCollision(agents.clone())
            );
        }
        assert!(EntryNames::new(&[format!("agents.{DOMAIN}")], Some(DOMAIN)).is_ok());
        assert!(EntryNames::new(&[format!("kube.{DOMAIN}")], Some(DOMAIN)).is_ok());
    }
}
