use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_tunnel::BoxFuture;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::client::{ApiError, SecretClient, SecretObject};
use super::{MirrorError, Restored, StateMirror};
use crate::pin::CaPin;
use crate::state::{
    CA_ROOT_FILE, INNER_CA_FILE, MANAGED_FILES, MAX_MIRRORED_FILE_BYTES, MirroredFile,
    SSH_HOST_KEY_FILE, STATE_FILE, StateDir, TLS_KEY_FILE, decode_host_key, decode_record,
    decode_tls_key,
};

pub const MAX_SECRET_BYTES: usize = 1024 * 1024;
pub const MAX_CONFLICTS: usize = 5;
const MAX_SHOWN_KEY: usize = 64;

#[derive(PartialEq, Eq)]
struct Identity {
    node_id: String,
    tls_key: Vec<u8>,
    host_key: Vec<u8>,
}

fn content<'a>(files: &'a [MirroredFile], name: &str) -> Option<&'a [u8]> {
    files
        .iter()
        .find(|file| file.name == name)
        .map(|file| file.content.as_slice())
}

fn identity(files: &[MirroredFile]) -> Option<Identity> {
    let record = decode_record(content(files, STATE_FILE)?, String::new).ok()?;
    Some(Identity {
        node_id: record.node_id,
        tls_key: Sha256::digest(content(files, TLS_KEY_FILE)?).to_vec(),
        host_key: Sha256::digest(content(files, SSH_HOST_KEY_FILE)?).to_vec(),
    })
}

fn shown_key(key: &str) -> String {
    key.chars()
        .take(MAX_SHOWN_KEY)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '?'
            }
        })
        .collect()
}

pub fn decode_entries(object: &SecretObject) -> Result<Vec<MirroredFile>, MirrorError> {
    if object.body_len() > MAX_SECRET_BYTES {
        return Err(MirrorError::TooLarge);
    }
    let Some(data) = object.data() else {
        return Ok(Vec::new());
    };
    let limit = usize::try_from(MAX_MIRRORED_FILE_BYTES).unwrap_or(usize::MAX);
    let encoded_limit = limit.div_ceil(3).saturating_mul(4);
    let mut files = Vec::with_capacity(data.len());
    for (key, value) in data {
        if key == INNER_CA_FILE {
            continue;
        }
        let name = MANAGED_FILES
            .into_iter()
            .find(|name| name == key)
            .ok_or_else(|| MirrorError::UnknownEntry {
                key: shown_key(key),
            })?;
        let text = value.as_str().ok_or(MirrorError::Encoding { key: name })?;
        if text.len() > encoded_limit {
            return Err(MirrorError::EntryTooLarge { key: name });
        }
        let decoded = Zeroizing::new(
            STANDARD
                .decode(text)
                .map_err(|_| MirrorError::Encoding { key: name })?,
        );
        if decoded.len() > limit {
            return Err(MirrorError::EntryTooLarge { key: name });
        }
        files.push(MirroredFile {
            name,
            content: decoded,
        });
    }
    Ok(files)
}

pub fn check_enrollment(
    files: &[MirroredFile],
    from: &str,
    ca_pin: &CaPin,
) -> Result<(), MirrorError> {
    let entry =
        |name: &'static str| content(files, name).ok_or(MirrorError::Incomplete { missing: name });
    for name in MANAGED_FILES {
        entry(name)?;
    }
    decode_record(entry(STATE_FILE)?, String::new).map_err(|_| MirrorError::Record)?;
    let label = |name: &'static str| move || format!("{from}, file {name},");
    decode_tls_key(entry(TLS_KEY_FILE)?, label(TLS_KEY_FILE)).map_err(MirrorError::Invalid)?;
    decode_host_key(entry(SSH_HOST_KEY_FILE)?, label(SSH_HOST_KEY_FILE))
        .map_err(MirrorError::Invalid)?;
    if !ca_pin.matches(entry(CA_ROOT_FILE)?) {
        return Err(MirrorError::PinMismatch);
    }
    Ok(())
}

fn held_by_another(object: &SecretObject, ours: &Identity) -> bool {
    match decode_entries(object) {
        Ok(files) => !files.is_empty() && identity(&files).as_ref() != Some(ours),
        Err(_) => true,
    }
}

fn encode(files: &[MirroredFile]) -> Map<String, Value> {
    files
        .iter()
        .map(|file| {
            (
                file.name.to_owned(),
                Value::String(STANDARD.encode(file.content.as_slice())),
            )
        })
        .collect()
}

pub struct KubernetesSecret {
    client: SecretClient,
    privileged: bool,
    ca_pin: CaPin,
    agent_uid: u32,
    latest: Mutex<Option<SecretObject>>,
}

impl KubernetesSecret {
    pub fn new(client: SecretClient, privileged: bool, ca_pin: CaPin, agent_uid: u32) -> Self {
        Self {
            client,
            privileged,
            ca_pin,
            agent_uid,
            latest: Mutex::new(None),
        }
    }

    pub fn secret(&self) -> &str {
        self.client.secret()
    }

    fn latest(&self) -> MutexGuard<'_, Option<SecretObject>> {
        self.latest.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn restore_into(&self, dir: &Path) -> Result<Restored, MirrorError> {
        let (state, _lock) = StateDir::prepare_enrollment(dir, self.privileged)?;
        if state.owner_uid()? != self.agent_uid {
            return Err(MirrorError::DirAccess {
                dir: dir.display().to_string(),
                uid: self.agent_uid,
            });
        }
        let object = self.client.get().await?;
        let files = decode_entries(&object)?;
        let restored = if files.is_empty() {
            Restored::Empty
        } else {
            let from = format!("the Secret {}", self.secret());
            check_enrollment(&files, &from, &self.ca_pin)?;
            state.restore_mirrored(&files)?;
            Restored::Enrollment
        };
        *self.latest() = Some(object);
        Ok(restored)
    }

    async fn probe_writable(&self) -> Result<(), MirrorError> {
        let current = self.latest().take();
        let object = match current {
            Some(object) => object,
            None => self.client.get().await?,
        };
        match self.client.put(&object).await {
            Ok(stored) => {
                *self.latest() = Some(stored);
                Ok(())
            }
            Err(error) => {
                *self.latest() = Some(object);
                Err(error.into())
            }
        }
    }

    async fn persist_from(&self, dir: &Path) -> Result<(), MirrorError> {
        let state = StateDir::open(dir, self.privileged)?;
        let files = state.read_mirrored()?;
        if let Some(missing) = MANAGED_FILES
            .into_iter()
            .find(|name| content(&files, name).is_none())
        {
            return Err(MirrorError::LocalIncomplete { missing });
        }
        let ours = identity(&files).ok_or(MirrorError::LocalIncomplete {
            missing: STATE_FILE,
        })?;
        let data = encode(&files);
        let mut current = self.latest().take();
        for _ in 0..MAX_CONFLICTS {
            let object = match current.take() {
                Some(object) => object,
                None => self.client.get().await?,
            };
            if held_by_another(&object, &ours) {
                return Err(MirrorError::Foreign);
            }
            match self.client.put(&object.with_data(data.clone())).await {
                Ok(stored) => {
                    *self.latest() = Some(stored);
                    return Ok(());
                }
                Err(ApiError::Conflict) => {}
                Err(error) => {
                    *self.latest() = Some(object);
                    return Err(error.into());
                }
            }
        }
        Err(MirrorError::Conflicts(MAX_CONFLICTS))
    }
}

impl StateMirror for KubernetesSecret {
    fn restore<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<Restored, MirrorError>> {
        Box::pin(self.restore_into(dir))
    }

    fn probe<'a>(&'a self) -> BoxFuture<'a, Result<(), MirrorError>> {
        Box::pin(self.probe_writable())
    }

    fn persist<'a>(&'a self, dir: &'a Path) -> BoxFuture<'a, Result<(), MirrorError>> {
        Box::pin(self.persist_from(dir))
    }
}
