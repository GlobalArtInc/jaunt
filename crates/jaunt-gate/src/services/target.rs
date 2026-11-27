use std::net::IpAddr;

use jaunt_proto::ServiceKind;
use jaunt_tunnel::{ServiceName, StreamKind};

use crate::ssh::{is_dns_label, normalize_dns_name};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SvcKind {
    Db,
    Tcp,
}

impl SvcKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Db => "db",
            Self::Tcp => "tcp",
        }
    }

    pub(crate) const fn service_kind(self) -> ServiceKind {
        match self {
            Self::Db => ServiceKind::Postgres,
            Self::Tcp => ServiceKind::Tcp,
        }
    }

    pub(crate) const fn stream_kind(self) -> StreamKind {
        match self {
            Self::Db => StreamKind::Db,
            Self::Tcp => StreamKind::Tcp,
        }
    }

    fn of_label(label: &str) -> Option<Self> {
        [Self::Db, Self::Tcp]
            .into_iter()
            .find(|kind| kind.label() == label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceTarget {
    pub(crate) kind: SvcKind,
    pub(crate) name: ServiceName,
}

pub(crate) fn service_target(server_name: Option<&str>, domain: &str) -> Option<ServiceTarget> {
    let name = normalize_dns_name(server_name?)?;
    if name.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels = name.strip_suffix(domain)?.strip_suffix('.')?;
    let (service, kind) = labels.split_once('.')?;
    let kind = SvcKind::of_label(kind)?;
    if !is_dns_label(service) {
        return None;
    }
    let name = ServiceName::new(service).ok()?;
    Some(ServiceTarget { kind, name })
}

#[cfg(test)]
mod tests {
    use super::{SvcKind, service_target};

    const DOMAIN: &str = "svc.example.com";

    #[test]
    fn only_one_service_label_and_a_db_or_tcp_label_under_the_domain_name_a_service() {
        let long = "s".repeat(63);
        let too_long = "s".repeat(64);
        let accepted: Vec<(String, SvcKind, &str)> = vec![
            (format!("lk.db.{DOMAIN}"), SvcKind::Db, "lk"),
            (format!("grafana.tcp.{DOMAIN}"), SvcKind::Tcp, "grafana"),
            (format!("LK-Ru.DB.{DOMAIN}."), SvcKind::Db, "lk-ru"),
            ("a1.tcp.SVC.Example.COM".to_owned(), SvcKind::Tcp, "a1"),
            (format!("{long}.db.{DOMAIN}"), SvcKind::Db, long.as_str()),
        ];
        for (given, kind, name) in accepted {
            let target = service_target(Some(&given), DOMAIN).unwrap_or_else(|| panic!("{given}"));
            assert_eq!(target.kind, kind, "{given}");
            assert_eq!(target.name.as_str(), name, "{given}");
        }
        let refused: Vec<Option<String>> = vec![
            None,
            Some(String::new()),
            Some(DOMAIN.to_owned()),
            Some(format!("db.{DOMAIN}")),
            Some(format!("tcp.{DOMAIN}")),
            Some(format!(".db.{DOMAIN}")),
            Some(format!("a.b.db.{DOMAIN}")),
            Some(format!("lk.kube.{DOMAIN}")),
            Some(format!("lk.ssh.{DOMAIN}")),
            Some(format!("lk.dbx.{DOMAIN}")),
            Some(format!("lk.xdb.{DOMAIN}")),
            Some(format!("lk.db.evil{DOMAIN}")),
            Some("lk.dbsvc.example.com".to_owned()),
            Some(format!("lk.db{DOMAIN}")),
            Some(format!("lk.db.{DOMAIN}.evil")),
            Some(format!("lk.db.{DOMAIN}..")),
            Some(format!("evil{DOMAIN}")),
            Some(format!("-lk.db.{DOMAIN}")),
            Some(format!("lk-.db.{DOMAIN}")),
            Some(format!("l_k.db.{DOMAIN}")),
            Some(format!("*.db.{DOMAIN}")),
            Some(format!("ä.db.{DOMAIN}")),
            Some(format!("{too_long}.db.{DOMAIN}")),
            Some("lk.db.svc.exämple.com".to_owned()),
            Some("lk.db.example.com".to_owned()),
            Some("192.0.2.7".to_owned()),
            Some("[2001:db8::1]".to_owned()),
            Some(format!("lk.db.{DOMAIN}:5432")),
            Some(format!("lk db.{DOMAIN}")),
        ];
        for given in refused {
            assert_eq!(service_target(given.as_deref(), DOMAIN), None, "{given:?}");
        }
    }

    #[test]
    fn a_name_longer_than_a_dns_name_is_refused() {
        let domain = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(56)
        );
        let fits = format!("x.db.{domain}");
        assert_eq!(fits.len(), 253);
        assert!(service_target(Some(&fits), &domain).is_some());
        assert_eq!(
            service_target(Some(&format!("xy.db.{domain}")), &domain),
            None
        );
    }

    #[test]
    fn kinds_map_to_the_control_kind_and_the_tunnel_kind() {
        assert_eq!(
            SvcKind::Db.service_kind(),
            jaunt_proto::ServiceKind::Postgres
        );
        assert_eq!(SvcKind::Tcp.service_kind(), jaunt_proto::ServiceKind::Tcp);
        assert_eq!(SvcKind::Db.stream_kind(), jaunt_tunnel::StreamKind::Db);
        assert_eq!(SvcKind::Tcp.stream_kind(), jaunt_tunnel::StreamKind::Tcp);
    }
}
