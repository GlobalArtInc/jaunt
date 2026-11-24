use jaunt_store::{
    ApproveEnrollment, ApproveOutcome, CertificateState, CodeFailure, Enrollment, Node, NodeState,
    RejectOutcome, Store, StoreError,
};

use crate::clock::{Clock, Moment};
use crate::enroll_secrets;
use crate::labels::Labels;
use crate::node_audit::{self, EnrollApproved};
use crate::node_keys;

const MAX_APPROVER_LEN: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum ApproveError {
    #[error("no pending enrollment matches this code")]
    UnknownCode,
    #[error("no pending enrollment matches this code")]
    Expired,
    #[error("the enrollment for this code was rejected")]
    Rejected,
    #[error("the enrollment for this code was already approved")]
    AlreadyApproved,
    #[error("the name {0:?} is held by an active node; the agent must enroll with replace")]
    NameTaken(String),
    #[error("the approver name is not valid")]
    InvalidApprover,
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the stored enrollment is not valid")]
    CorruptEnrollment,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

impl From<StoreError> for ApproveError {
    fn from(err: StoreError) -> ApproveError {
        ApproveError::Store(err)
    }
}

impl From<CodeFailure> for ApproveError {
    fn from(failure: CodeFailure) -> ApproveError {
        match failure {
            CodeFailure::Unknown => ApproveError::UnknownCode,
            CodeFailure::Expired => ApproveError::Expired,
            CodeFailure::Rejected => ApproveError::Rejected,
            CodeFailure::AlreadyApproved => ApproveError::AlreadyApproved,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoveError {
    #[error("no active node has this name")]
    NoActiveNode,
    #[error("the operator name is not valid")]
    InvalidOperator,
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("the database failed: {0}")]
    Store(#[source] StoreError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeListing {
    pub node: NodeSummary,
    pub certificates: CertificateState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub id: String,
    pub name: String,
    pub labels: Labels,
    pub hostname: String,
    pub peer_addr: String,
    pub source_network: String,
    pub requested_at: i64,
    pub expires_at: i64,
    pub tls_key_sha256: String,
    pub ssh_host_key_fingerprint: String,
    pub replace_existing: bool,
    pub agent_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSummary {
    pub id: String,
    pub name: String,
    pub state: NodeState,
    pub labels: Labels,
    pub hostname: String,
    pub approved_by: String,
    pub created_at: i64,
    pub removed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedNode {
    pub enrollment_id: String,
    pub node: NodeSummary,
    pub replaced: Option<NodeSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedEnrollment {
    pub id: String,
    pub name: String,
}

#[derive(Clone)]
pub struct NodeAdmin {
    store: Store,
    clock: Clock,
}

impl NodeAdmin {
    pub fn new(store: Store, clock: Clock) -> NodeAdmin {
        NodeAdmin { store, clock }
    }

    pub async fn pending(&self, code: &str) -> Result<PendingEnrollment, ApproveError> {
        let now = self.now().ok_or(ApproveError::Clock)?;
        let code_hash = hash_typed_code(code)?;
        let enrollment = self.find_pending(&code_hash, now).await?;
        pending_view(&enrollment)
    }

    pub async fn approve(
        &self,
        code: &str,
        approver: &str,
        labels_override: Option<Labels>,
    ) -> Result<ApprovedNode, ApproveError> {
        if !is_valid_approver(approver) {
            return Err(ApproveError::InvalidApprover);
        }
        let now = self.now().ok_or(ApproveError::Clock)?;
        let code_hash = hash_typed_code(code)?;
        let pending = self.find_pending(&code_hash, now).await?;
        let tls =
            node_keys::parse_tls(&pending.tls_public_key).ok_or(ApproveError::CorruptEnrollment)?;
        let ssh = node_keys::parse_ssh(&pending.ssh_host_public_key)
            .ok_or(ApproveError::CorruptEnrollment)?;
        let override_map = labels_override.map(Labels::into_map);

        let outcome = self
            .store
            .enrollments()
            .approve_enrollment(ApproveEnrollment {
                enrollment_id: &pending.id,
                code_hash: &code_hash,
                approver,
                labels_override: override_map.as_ref(),
                tls_spki_sha256: &tls.sha256,
                ssh_host_key_fingerprint: &ssh.fingerprint,
                now: now.secs,
            })
            .await?;
        match outcome {
            ApproveOutcome::Approved(approved) => {
                let replaced_id = approved.replaced.as_ref().map(|node| node.id.as_str());
                node_audit::enroll_approved(&EnrollApproved {
                    enrollment_id: &approved.enrollment.id,
                    node_id: &approved.node.id,
                    name: &approved.node.name,
                    approved_by: approver,
                    replaced_node_id: replaced_id,
                });
                if let Some(old) = &approved.replaced {
                    node_audit::node_removed(&old.id, &old.name, "replaced", approver);
                }
                Ok(ApprovedNode {
                    enrollment_id: approved.enrollment.id.clone(),
                    node: summary(approved.node.clone())?,
                    replaced: approved.replaced.clone().map(summary).transpose()?,
                })
            }
            ApproveOutcome::NameTaken => Err(ApproveError::NameTaken(pending.name)),
            ApproveOutcome::Refused(failure) => Err(failure.into()),
        }
    }

    pub async fn reject(
        &self,
        code: &str,
        rejected_by: &str,
    ) -> Result<RejectedEnrollment, ApproveError> {
        if !is_valid_approver(rejected_by) {
            return Err(ApproveError::InvalidApprover);
        }
        let now = self.now().ok_or(ApproveError::Clock)?;
        let code_hash = hash_typed_code(code)?;
        match self
            .store
            .enrollments()
            .reject_by_code(&code_hash, now.secs)
            .await?
        {
            RejectOutcome::Rejected(enrollment) => {
                node_audit::enroll_rejected(&enrollment.id, &enrollment.name, rejected_by);
                Ok(RejectedEnrollment {
                    id: enrollment.id,
                    name: enrollment.name,
                })
            }
            RejectOutcome::Refused(failure) => Err(failure.into()),
        }
    }

    pub async fn remove_node(
        &self,
        name: &str,
        removed_by: &str,
    ) -> Result<NodeSummary, RemoveError> {
        if !is_valid_approver(removed_by) {
            return Err(RemoveError::InvalidOperator);
        }
        let now = self.now().ok_or(RemoveError::Clock)?;
        let removed = self
            .store
            .nodes()
            .remove_by_name(name, now.secs)
            .await
            .map_err(RemoveError::Store)?
            .ok_or(RemoveError::NoActiveNode)?;
        node_audit::node_removed(&removed.id, &removed.name, "admin", removed_by);
        summary(removed).map_err(RemoveError::Store)
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeListing>, ListError> {
        let now = self.now().ok_or(ListError::Clock)?;
        let nodes = self.store.nodes();
        let listed = nodes.list().await.map_err(ListError::Store)?;
        let states = nodes
            .certificate_states(now.secs)
            .await
            .map_err(ListError::Store)?;
        listed
            .into_iter()
            .map(|node| {
                let certificates = states
                    .get(&node.id)
                    .copied()
                    .unwrap_or(CertificateState::None);
                Ok(NodeListing {
                    node: summary(node).map_err(ListError::Store)?,
                    certificates,
                })
            })
            .collect()
    }

    fn now(&self) -> Option<Moment> {
        Moment::read(&self.clock)
    }

    async fn find_pending(&self, code_hash: &str, now: Moment) -> Result<Enrollment, ApproveError> {
        let enrollments = self.store.enrollments();
        match enrollments
            .find_pending_by_code(code_hash, now.secs)
            .await?
        {
            Some(enrollment) => Ok(enrollment),
            None => Err(enrollments.classify_code(code_hash, now.secs).await?.into()),
        }
    }
}

fn hash_typed_code(code: &str) -> Result<String, ApproveError> {
    let normalized = enroll_secrets::normalize_code(code).ok_or(ApproveError::UnknownCode)?;
    Ok(enroll_secrets::hash_code(&normalized))
}

fn is_valid_approver(approver: &str) -> bool {
    !approver.is_empty()
        && approver.len() <= MAX_APPROVER_LEN
        && approver.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn summary(node: Node) -> Result<NodeSummary, StoreError> {
    let labels = Labels::new(node.labels)
        .map_err(|_| StoreError::Corrupt("nodes.labels: not valid".to_owned()))?;
    Ok(NodeSummary {
        id: node.id,
        name: node.name,
        state: node.state,
        labels,
        hostname: node.hostname,
        approved_by: node.approved_by,
        created_at: node.created_at,
        removed_at: node.removed_at,
    })
}

fn pending_view(enrollment: &Enrollment) -> Result<PendingEnrollment, ApproveError> {
    let tls =
        node_keys::parse_tls(&enrollment.tls_public_key).ok_or(ApproveError::CorruptEnrollment)?;
    let ssh = node_keys::parse_ssh(&enrollment.ssh_host_public_key)
        .ok_or(ApproveError::CorruptEnrollment)?;
    let labels =
        Labels::new(enrollment.labels.clone()).map_err(|_| ApproveError::CorruptEnrollment)?;
    Ok(PendingEnrollment {
        id: enrollment.id.clone(),
        name: enrollment.name.clone(),
        labels,
        hostname: enrollment.hostname.clone(),
        peer_addr: enrollment.peer_addr.clone(),
        source_network: enrollment.source_ip.clone(),
        requested_at: enrollment.created_at,
        expires_at: enrollment.expires_at,
        tls_key_sha256: tls.sha256,
        ssh_host_key_fingerprint: ssh.fingerprint,
        replace_existing: enrollment.replace_existing,
        agent_version: enrollment.agent_version.clone(),
    })
}
