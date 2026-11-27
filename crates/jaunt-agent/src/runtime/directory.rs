use std::sync::Arc;

use jaunt_proto::{ServiceAnnouncement, ServiceKind};
use jaunt_tunnel::{ServedKinds, ServiceName, StreamKind};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::certs::ServiceCertificates;
use super::handler::HandlerRegistry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedService {
    pub id: String,
    pub kind: StreamKind,
    pub name: ServiceName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    pub service: ApprovedService,
    pub address: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceDirectory(Vec<ServiceEntry>);

pub const fn stream_kind(kind: ServiceKind) -> StreamKind {
    match kind {
        ServiceKind::Kubernetes => StreamKind::Kube,
        ServiceKind::Postgres => StreamKind::Db,
        ServiceKind::Tcp => StreamKind::Tcp,
    }
}

pub const fn service_kind(kind: StreamKind) -> Option<ServiceKind> {
    match kind {
        StreamKind::Kube => Some(ServiceKind::Kubernetes),
        StreamKind::Db => Some(ServiceKind::Postgres),
        StreamKind::Tcp => Some(ServiceKind::Tcp),
        StreamKind::Ssh => None,
    }
}

impl ServiceDirectory {
    pub fn new(local: &ServiceAnnouncement, approved: &[ApprovedService]) -> Self {
        let mut entries: Vec<ServiceEntry> = Vec::new();
        for service in approved {
            let declared = local.services.iter().find(|declared| {
                stream_kind(declared.kind) == service.kind && declared.name == service.name.as_str()
            });
            let Some(declared) = declared else {
                continue;
            };
            let taken = entries.iter().any(|entry| {
                entry.service.id == service.id
                    || (entry.service.kind == service.kind && entry.service.name == service.name)
            });
            if taken {
                tracing::warn!(
                    target: "jaunt::agent",
                    kind = service.kind.as_str(),
                    service = %service.name,
                    "the control plane approved the same service twice; only the first approval is served"
                );
                continue;
            }
            entries.push(ServiceEntry {
                service: service.clone(),
                address: declared.address.clone(),
            });
        }
        Self(entries)
    }

    pub fn find(&self, kind: StreamKind, name: &ServiceName) -> Option<&ServiceEntry> {
        self.0
            .iter()
            .find(|entry| entry.service.kind == kind && &entry.service.name == name)
    }

    pub fn contains_id(&self, id: &str) -> bool {
        self.0.iter().any(|entry| entry.service.id == id)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn served_kinds(
        &self,
        ssh_enabled: bool,
        handlers: &HandlerRegistry,
    ) -> Option<ServedKinds> {
        let ssh = ssh_enabled.then_some(StreamKind::Ssh);
        let services = self
            .0
            .iter()
            .map(|entry| entry.service.kind)
            .filter(|kind| handlers.get(*kind).is_some());
        ServedKinds::new(ssh.into_iter().chain(services)).ok()
    }
}

pub struct Approvals {
    pub local: Arc<ServiceAnnouncement>,
    pub handlers: Arc<HandlerRegistry>,
    pub directory: watch::Sender<Arc<ServiceDirectory>>,
    pub served: watch::Sender<Option<ServedKinds>>,
    pub certificates: Arc<ServiceCertificates>,
}

impl Approvals {
    pub fn publish(&self, approved: &[ApprovedService]) {
        let directory = Arc::new(ServiceDirectory::new(&self.local, approved));
        let served = directory.served_kinds(self.local.ssh_enabled, &self.handlers);
        tracing::info!(
            target: "jaunt::agent",
            approved = directory.len(),
            served = ?served.as_ref().map(ServedKinds::as_slice),
            "the approved services of this node changed"
        );
        self.directory.send_if_modified(|current| {
            if **current == *directory {
                return false;
            }
            *current = Arc::clone(&directory);
            true
        });
        self.served.send_if_modified(|current| {
            if *current == served {
                return false;
            }
            *current = served;
            true
        });
        self.certificates
            .retain(|service| directory.contains_id(&service.id));
    }

    pub async fn follow(
        self,
        mut approvals: watch::Receiver<Vec<ApprovedService>>,
        stop: CancellationToken,
    ) {
        loop {
            tokio::select! {
                () = stop.cancelled() => return,
                changed = approvals.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
            }
            let current = approvals.borrow_and_update().clone();
            self.publish(&current);
        }
    }
}
