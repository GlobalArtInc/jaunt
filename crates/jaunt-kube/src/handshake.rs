use http::header::{HeaderMap, HeaderValue, SEC_WEBSOCKET_EXTENSIONS, SEC_WEBSOCKET_PROTOCOL};
use thiserror::Error;

use crate::channel::ChannelProtocol;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SubprotocolError {
    #[error("the upgrade response names no websocket subprotocol")]
    Missing,
    #[error("the upgrade response names more than one websocket subprotocol")]
    Ambiguous,
    #[error("the upgrade response subprotocol is not readable")]
    Unreadable,
    #[error("the upgrade response subprotocol is not supported")]
    Unsupported,
    #[error("the upgrade response subprotocol differs from the one offered")]
    Mismatch,
}

pub fn select_offered_subprotocol(headers: &HeaderMap) -> Option<ChannelProtocol> {
    headers
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|offer| ChannelProtocol::from_subprotocol(offer.trim_matches([' ', '\t'])))
}

pub fn rewrite_subprotocol_offer(headers: &mut HeaderMap) -> Option<ChannelProtocol> {
    let selected = select_offered_subprotocol(headers);
    headers.remove(SEC_WEBSOCKET_PROTOCOL);
    if let Some(protocol) = selected {
        headers.insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(protocol.as_str()),
        );
    }
    selected
}

pub fn protocol_from_response(
    headers: &HeaderMap,
    offered: ChannelProtocol,
) -> Result<ChannelProtocol, SubprotocolError> {
    let mut values = headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter();
    let value = values.next().ok_or(SubprotocolError::Missing)?;
    if values.next().is_some() {
        return Err(SubprotocolError::Ambiguous);
    }
    let text = value
        .to_str()
        .map_err(|_| SubprotocolError::Unreadable)?
        .trim_matches([' ', '\t']);
    if text.is_empty() {
        return Err(SubprotocolError::Missing);
    }
    if text.contains(',') {
        return Err(SubprotocolError::Ambiguous);
    }
    let protocol = ChannelProtocol::from_subprotocol(text).ok_or(SubprotocolError::Unsupported)?;
    if protocol != offered {
        return Err(SubprotocolError::Mismatch);
    }
    Ok(protocol)
}

pub fn strip_websocket_extensions(headers: &mut HeaderMap) -> bool {
    headers.remove(SEC_WEBSOCKET_EXTENSIONS).is_some()
}
