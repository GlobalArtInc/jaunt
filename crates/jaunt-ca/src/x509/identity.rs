use uuid::Uuid;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::error::CaError;

const NODE_URN_PREFIX: &str = "urn:jaunt:node:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeIdentity {
    pub node_id: Uuid,
}

pub fn parse_node_identity(cert_der: &[u8]) -> Result<NodeIdentity, CaError> {
    let (rest, certificate) =
        parse_x509_certificate(cert_der).map_err(|_| CaError::InvalidNodeIdentity)?;
    if !rest.is_empty() {
        return Err(CaError::InvalidNodeIdentity);
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| CaError::InvalidNodeIdentity)?
        .ok_or(CaError::InvalidNodeIdentity)?;
    let [GeneralName::URI(uri)] = san.value.general_names.as_slice() else {
        return Err(CaError::InvalidNodeIdentity);
    };
    let node_id = node_id_from_urn(uri).ok_or(CaError::InvalidNodeIdentity)?;
    Ok(NodeIdentity { node_id })
}

pub(super) fn node_urn(node_id: Uuid) -> String {
    format!("{NODE_URN_PREFIX}{}", node_id.hyphenated())
}

fn node_id_from_urn(uri: &str) -> Option<Uuid> {
    let text = uri.strip_prefix(NODE_URN_PREFIX)?;
    let node_id = Uuid::parse_str(text).ok()?;
    let canonical = !node_id.is_nil() && node_id.hyphenated().to_string() == text;
    canonical.then_some(node_id)
}
