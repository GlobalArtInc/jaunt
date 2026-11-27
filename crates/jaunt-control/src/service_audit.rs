use jaunt_store::{Labels, Service, ServiceChange};

fn labels_text(labels: &Labels) -> String {
    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn ssh_changed(node_id: &str, ssh_enabled: bool) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.ssh_changed",
        node_id,
        ssh_enabled
    );
}

pub(crate) fn announce_refused(node_id: &str, reason: &'static str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "service.announce_refused",
        node_id,
        reason
    );
}

pub(crate) fn changed(change: &ServiceChange) {
    match change {
        ServiceChange::Requested(service) => {
            let labels = labels_text(&service.announced_labels);
            tracing::info!(
                target: "jaunt::audit",
                event = "service.requested",
                node_id = service.node_id.as_str(),
                service_id = service.id.as_str(),
                kind = service.kind.as_str(),
                name = service.name.as_str(),
                revision = service.revision,
                labels = labels.as_str()
            );
        }
        ServiceChange::Superseded(service) => tracing::info!(
            target: "jaunt::audit",
            event = "service.superseded",
            node_id = service.node_id.as_str(),
            service_id = service.id.as_str(),
            kind = service.kind.as_str(),
            name = service.name.as_str(),
            revision = service.revision
        ),
        ServiceChange::Withdrawn(service) => tracing::info!(
            target: "jaunt::audit",
            event = "service.withdrawn",
            node_id = service.node_id.as_str(),
            service_id = service.id.as_str(),
            kind = service.kind.as_str(),
            name = service.name.as_str(),
            revision = service.revision,
            state = service.state.as_str()
        ),
        ServiceChange::Reannounced(service) => tracing::info!(
            target: "jaunt::audit",
            event = "service.reannounced",
            node_id = service.node_id.as_str(),
            service_id = service.id.as_str(),
            kind = service.kind.as_str(),
            name = service.name.as_str(),
            revision = service.revision,
            state = service.state.as_str()
        ),
    }
}

pub(crate) fn approved(
    service: &Service,
    approved_by: &str,
    overridden: bool,
    replaced: Option<&Service>,
) {
    let labels = labels_text(&service.labels);
    tracing::info!(
        target: "jaunt::audit",
        event = "service.approved",
        node_id = service.node_id.as_str(),
        approved_by,
        service_id = service.id.as_str(),
        kind = service.kind.as_str(),
        name = service.name.as_str(),
        revision = service.revision,
        labels = labels.as_str(),
        labels_overridden = overridden,
        replaced_id = replaced.map(|old| old.id.as_str())
    );
}

pub(crate) fn rejected(service: &Service, rejected_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "service.rejected",
        node_id = service.node_id.as_str(),
        rejected_by,
        service_id = service.id.as_str(),
        kind = service.kind.as_str(),
        name = service.name.as_str(),
        revision = service.revision
    );
}

pub(crate) fn removed(service: &Service, removed_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "service.removed",
        node_id = service.node_id.as_str(),
        removed_by,
        service_id = service.id.as_str(),
        kind = service.kind.as_str(),
        name = service.name.as_str(),
        revision = service.revision
    );
}
