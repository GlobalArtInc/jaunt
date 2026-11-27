use std::sync::Arc;
use std::time::SystemTime;

use jaunt_tunnel::{ServiceName, StreamKind};
use tokio::sync::watch;

use super::support::{
    Behaviour, FakeServiceControl, TCP_ADDRESS, TestHandler, approved, fixed, local_services,
};
use crate::runtime::certs::{SERVICE_CERTIFICATE_BACKOFF, ServiceCertificates};
use crate::runtime::directory::{Approvals, ApprovedService, ServiceDirectory};
use crate::runtime::handler::HandlerRegistry;
use crate::testkit::{ManualClock, TestPki};

#[test]
fn only_approved_declared_services_with_a_handler_are_served() {
    let grafana = approved(StreamKind::Tcp, "grafana");
    let billing = approved(StreamKind::Db, "billing");
    let prod = approved(StreamKind::Kube, "prod-eu");
    let local = local_services(&[grafana.clone(), billing.clone()]);
    let mut handlers = HandlerRegistry::default();
    handlers
        .register(StreamKind::Tcp, TestHandler::new(Behaviour::Echo))
        .unwrap();
    handlers
        .register(StreamKind::Kube, TestHandler::new(Behaviour::Echo))
        .unwrap();
    assert!(
        handlers
            .register(StreamKind::Ssh, TestHandler::new(Behaviour::Echo))
            .is_err()
    );
    let kinds = |ssh: bool, approved: &[ApprovedService]| {
        ServiceDirectory::new(&local, approved)
            .served_kinds(ssh, &handlers)
            .map(|kinds| kinds.as_slice().to_vec())
    };
    assert_eq!(kinds(true, &[]), Some(vec![StreamKind::Ssh]));
    assert_eq!(kinds(false, &[]), None);
    assert_eq!(kinds(false, std::slice::from_ref(&billing)), None);
    assert_eq!(kinds(false, &[prod]), None);
    assert_eq!(
        kinds(true, &[grafana.clone(), billing]),
        Some(vec![StreamKind::Ssh, StreamKind::Tcp])
    );
    let directory = ServiceDirectory::new(&local, std::slice::from_ref(&grafana));
    let entry = directory
        .find(StreamKind::Tcp, &ServiceName::new("grafana").unwrap())
        .unwrap();
    assert_eq!(entry.service, grafana);
    assert_eq!(entry.address.as_deref(), Some(TCP_ADDRESS));
    assert!(
        directory
            .find(StreamKind::Kube, &ServiceName::new("grafana").unwrap())
            .is_none()
    );
}

#[test]
fn a_second_approval_of_the_same_service_is_ignored() {
    let grafana = approved(StreamKind::Tcp, "grafana");
    let local = local_services(std::slice::from_ref(&grafana));
    let twin = ApprovedService {
        id: "id-other".to_owned(),
        ..grafana.clone()
    };
    let directory = ServiceDirectory::new(&local, &[grafana.clone(), twin]);
    assert_eq!(directory.len(), 1);
    assert!(directory.contains_id(&grafana.id));
    assert!(!directory.contains_id("id-other"));
}

#[tokio::test]
async fn a_withdrawn_approval_drops_the_service_and_its_certificate() {
    let grafana = approved(StreamKind::Tcp, "grafana");
    let clock = ManualClock::new(SystemTime::now());
    let control = Arc::new(FakeServiceControl::new(
        Arc::new(TestPki::new()),
        clock.clone(),
        std::slice::from_ref(&grafana),
    ));
    let certificates = Arc::new(ServiceCertificates::new(
        control,
        clock,
        fixed(1.0),
        SERVICE_CERTIFICATE_BACKOFF,
    ));
    let mut handlers = HandlerRegistry::default();
    handlers
        .register(StreamKind::Tcp, TestHandler::new(Behaviour::Echo))
        .unwrap();
    let (directory, directory_changes) = watch::channel(Arc::new(ServiceDirectory::default()));
    let (served, served_changes) = watch::channel(None);
    let approvals = Approvals {
        local: Arc::new(local_services(std::slice::from_ref(&grafana))),
        handlers: Arc::new(handlers),
        directory,
        served,
        certificates: certificates.clone(),
    };
    approvals.publish(std::slice::from_ref(&grafana));
    certificates.get(&grafana).await.unwrap();
    assert!(certificates.slot_serial(&grafana).is_some());
    assert_eq!(directory_changes.borrow().len(), 1);
    assert!(served_changes.borrow().is_some());

    let mut directory_changes = directory_changes;
    let mut served_changes = served_changes;
    directory_changes.mark_unchanged();
    served_changes.mark_unchanged();
    approvals.publish(std::slice::from_ref(&grafana));
    assert!(!directory_changes.has_changed().unwrap());
    assert!(!served_changes.has_changed().unwrap());
    assert!(certificates.slot_serial(&grafana).is_some());

    approvals.publish(&[]);
    assert!(directory_changes.has_changed().unwrap());
    assert!(served_changes.has_changed().unwrap());
    assert!(certificates.slot_serial(&grafana).is_none());
    assert_eq!(directory_changes.borrow().len(), 0);
    assert!(served_changes.borrow().is_none());
}
