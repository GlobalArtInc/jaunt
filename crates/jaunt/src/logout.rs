use crate::agent::{AgentError, SshAgent};
use crate::store::{ProfileStore, StoreError};

#[derive(Debug)]
pub struct LogoutReport {
    pub was_signed_in: bool,
    pub directory_kept: bool,
    pub agent_warning: Option<AgentError>,
}

pub fn logout(store: &ProfileStore, agent: &SshAgent) -> Result<LogoutReport, StoreError> {
    let public_key = store.public_key_path();
    let agent_warning = if public_key.exists() && agent.is_configured() {
        agent.remove(&public_key).err()
    } else {
        None
    };
    let cleared = store.clear()?;
    Ok(LogoutReport {
        was_signed_in: cleared.removed_any,
        directory_kept: cleared.directory_kept,
        agent_warning,
    })
}
