pub(crate) struct X509Issued<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) serial: i64,
    pub(crate) parent_serial: i64,
    pub(crate) valid_before: i64,
    pub(crate) client_addr: Option<&'a str>,
}

pub(crate) fn x509_issued(issued: &X509Issued<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.x509.issued",
        user_id = issued.user_id,
        serial = issued.serial,
        parent_serial = issued.parent_serial,
        valid_before = issued.valid_before,
        client_addr = issued.client_addr
    );
}

pub(crate) struct ServiceIssued<'a> {
    pub(crate) node_id: &'a str,
    pub(crate) service_id: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) name: &'a str,
    pub(crate) serial: i64,
    pub(crate) valid_before: i64,
}

pub(crate) fn service_issued(issued: &ServiceIssued<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.service.issued",
        node_id = issued.node_id,
        service_id = issued.service_id,
        kind = issued.kind,
        name = issued.name,
        serial = issued.serial,
        valid_before = issued.valid_before
    );
}

pub(crate) fn gate_issued(serial: i64, valid_before: i64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.gate.issued",
        serial,
        valid_before
    );
}

pub(crate) fn service_refused(node_id: &str, service_id: Option<&str>, reason: &'static str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.service.refused",
        node_id,
        service_id,
        reason
    );
}
