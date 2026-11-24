pub(crate) struct EnrollRequested<'a> {
    pub(crate) enrollment_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) hostname: &'a str,
    pub(crate) source_ip: &'a str,
    pub(crate) source_network: &'a str,
    pub(crate) agent_version: &'a str,
    pub(crate) replace: bool,
}

pub(crate) struct EnrollApproved<'a> {
    pub(crate) enrollment_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) approved_by: &'a str,
    pub(crate) replaced_node_id: Option<&'a str>,
}

pub(crate) struct Delivered<'a> {
    pub(crate) enrollment_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) x509_serial: &'a str,
    pub(crate) ssh_serial: &'a str,
}

pub(crate) struct Renewed<'a> {
    pub(crate) node_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) x509_serial: &'a str,
    pub(crate) ssh_serial: &'a str,
    pub(crate) rotated: bool,
}

pub(crate) fn enroll_requested(event: &EnrollRequested<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.enroll.requested",
        enrollment_id = event.enrollment_id,
        name = event.name,
        hostname = event.hostname,
        source_ip = event.source_ip,
        source_network = event.source_network,
        agent_version = event.agent_version,
        replace = event.replace
    );
}

pub(crate) fn enroll_approved(event: &EnrollApproved<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.enroll.approved",
        enrollment_id = event.enrollment_id,
        node_id = event.node_id,
        name = event.name,
        approved_by = event.approved_by,
        replaced_node_id = event.replaced_node_id
    );
}

pub(crate) fn enroll_rejected(enrollment_id: &str, name: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.enroll.rejected",
        enrollment_id,
        name
    );
}

pub(crate) fn enroll_expired(enrollment_id: &str, name: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.enroll.expired",
        enrollment_id,
        name
    );
}

pub(crate) fn enroll_delivered(event: &Delivered<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.enroll.delivered",
        enrollment_id = event.enrollment_id,
        node_id = event.node_id,
        name = event.name,
        x509_serial = event.x509_serial,
        ssh_serial = event.ssh_serial
    );
}

pub(crate) fn node_removed(node_id: &str, name: &str, reason: &'static str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.removed",
        node_id,
        name,
        reason
    );
}

pub(crate) fn cert_renewed(event: &Renewed<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "node.cert.renewed",
        node_id = event.node_id,
        name = event.name,
        x509_serial = event.x509_serial,
        ssh_serial = event.ssh_serial,
        rotated = event.rotated
    );
}
