use std::time::{SystemTime, UNIX_EPOCH};

use jaunt_ca::{
    CaError, DEFAULT_HOST_VALIDITY, DEFAULT_NODE_VALIDITY, HostCertParams, NodeCertParams, Uuid,
    sign_host_certificate,
};
use jaunt_store::{NewNodeCertificate, NodeCertificateKind, StoreError};

use crate::clock::Moment;
use crate::control::Control;
use crate::finish::key_fingerprint;
use crate::node_keys::{SshHostKey, TlsKey};

#[derive(Debug, thiserror::Error)]
pub(crate) enum IssueError {
    #[error("the node id is not a uuid")]
    NodeId,
    #[error("allocating a serial failed: {0}")]
    Serial(#[source] StoreError),
    #[error("the serial counter is not positive")]
    SerialRange,
    #[error("a certificate validity time does not fit the record")]
    Time,
    #[error("signing failed: {0}")]
    Signing(#[source] CaError),
    #[error("encoding the host certificate failed: {0}")]
    Encoding(#[source] jaunt_ca::ssh_key::Error),
}

pub(crate) struct Bundle {
    pub(crate) x509_der: Vec<u8>,
    pub(crate) x509_serial: String,
    pub(crate) x509_not_before: i64,
    pub(crate) x509_not_after: i64,
    pub(crate) ssh_line: String,
    pub(crate) ssh_serial: String,
    pub(crate) ssh_not_before: i64,
    pub(crate) ssh_not_after: i64,
    pub(crate) ssh_ca_fingerprint: String,
}

impl Bundle {
    pub(crate) fn records(&self, issued_at: i64) -> [NewNodeCertificate; 2] {
        [
            NewNodeCertificate {
                kind: NodeCertificateKind::X509,
                serial: self.x509_serial.clone(),
                not_before: self.x509_not_before,
                not_after: self.x509_not_after,
                issued_at,
                ca_fingerprint: None,
            },
            NewNodeCertificate {
                kind: NodeCertificateKind::SshHost,
                serial: self.ssh_serial.clone(),
                not_before: self.ssh_not_before,
                not_after: self.ssh_not_after,
                issued_at,
                ca_fingerprint: Some(self.ssh_ca_fingerprint.clone()),
            },
        ]
    }
}

pub(crate) async fn issue(
    control: &Control,
    node_id: &str,
    name: &str,
    tls: &TlsKey,
    ssh: &SshHostKey,
    now: Moment,
) -> Result<Bundle, IssueError> {
    let node_uuid = Uuid::parse_str(node_id).map_err(|_| IssueError::NodeId)?;
    let ca = control.ca_snapshot();
    let x509 = control
        .internal_ca
        .issue_node_certificate(
            NodeCertParams {
                subject_public_key: tls.subject.clone(),
                node_id: node_uuid,
                validity: DEFAULT_NODE_VALIDITY,
            },
            now.system,
        )
        .map_err(IssueError::Signing)?;

    let serial = control
        .store
        .certificates()
        .allocate_serial()
        .await
        .map_err(IssueError::Serial)?;
    let serial_number = u64::try_from(serial).map_err(|_| IssueError::SerialRange)?;
    let host_certificate = sign_host_certificate(
        ca.host_signer().as_ref(),
        HostCertParams {
            subject_public_key: ssh.key.clone(),
            hostnames: vec![
                format!("{name}.{}", control.ssh_suffix.as_str()),
                name.to_owned(),
            ],
            serial: serial_number,
            validity: DEFAULT_HOST_VALIDITY,
        },
        now.system,
    )
    .map_err(IssueError::Signing)?;
    let ssh_line = host_certificate
        .to_openssh()
        .map_err(IssueError::Encoding)?;

    Ok(Bundle {
        x509_der: x509.certificate_der,
        x509_serial: format!("{:x}", x509.serial),
        x509_not_before: unix_secs(x509.not_before)?,
        x509_not_after: unix_secs(x509.not_after)?,
        ssh_line,
        ssh_serial: format!("{serial_number:x}"),
        ssh_not_before: i64::try_from(host_certificate.valid_after())
            .map_err(|_| IssueError::Time)?,
        ssh_not_after: i64::try_from(host_certificate.valid_before())
            .map_err(|_| IssueError::Time)?,
        ssh_ca_fingerprint: key_fingerprint(host_certificate.signature_key()),
    })
}

fn unix_secs(time: SystemTime) -> Result<i64, IssueError> {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IssueError::Time)?
        .as_secs();
    i64::try_from(secs).map_err(|_| IssueError::Time)
}
