use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};

use super::{RecordingKey, RecordingSink, RecordingStoreError, cast_sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastProof {
    pub bytes: u64,
    pub sha256: String,
}

impl CastProof {
    pub fn of(bytes: u64, sha256: impl Into<String>) -> Option<CastProof> {
        (bytes > 0).then(|| CastProof {
            bytes,
            sha256: sha256.into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub session_id: String,
    pub node: String,
    pub user: String,
    pub login: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct LocalProof<'a> {
    pub manifest: Option<&'a SessionManifest>,
    pub cast: Option<&'a CastProof>,
    pub chunks: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct StoreProof {
    pub manifest: SessionManifest,
    pub manifest_sha256: String,
    pub cast_bytes: u64,
    pub cast_sha256: Option<String>,
}

impl StoreProof {
    pub fn cast(&self) -> Option<CastProof> {
        self.cast_sha256
            .as_ref()
            .and_then(|sha256| CastProof::of(self.cast_bytes, sha256.clone()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    Nothing,
    Adopt,
    Conflict(&'static str),
    Retry,
}

pub const IDENTITY_CONFLICT: &str =
    "the stored manifest belongs to another session, node, user or login";
pub const UNREADABLE_CONFLICT: &str = "the stored recording cannot be read as a manifest";
pub const LENGTH_CONFLICT: &str = "the stored cast is longer than its manifest says";
pub const CAST_CONFLICT: &str = "the cast in the recording storage differs from the staged cast";
pub const STRUCTURE_CONFLICT: &str =
    "the stored manifest is not a well formed record of the stored cast";
pub const MANIFEST_CONFLICT: &str =
    "the manifest in the recording storage disagrees with the verified one";

pub fn read_store_proof(
    sink: &dyn RecordingSink,
    key: &RecordingKey,
) -> Result<Option<StoreProof>, RecordingStoreError> {
    let Some(mut stored) = sink.open(key)? else {
        return Ok(None);
    };
    let (cast_bytes, cast_sha256) = match stored.cast.as_mut() {
        Some(cast) => {
            let (bytes, sha256) = cast_sha256(cast)?;
            (bytes, Some(sha256))
        }
        None => (0, None),
    };
    Ok(Some(StoreProof {
        manifest: stored.manifest,
        manifest_sha256: stored.manifest_sha256,
        cast_bytes,
        cast_sha256,
    }))
}

fn is_lost_acknowledgement(expected: &SessionManifest, found: &SessionManifest) -> bool {
    found.incomplete
        && found.digest.is_none()
        && found.kind == expected.kind
        && found.chunks <= expected.chunks
}

fn agree(expected: &SessionManifest, found: &SessionManifest) -> bool {
    let common = expected.kind == found.kind
        && expected.chunks == found.chunks
        && expected.raw_bytes == found.raw_bytes
        && expected.digest == found.digest
        && expected.incomplete == found.incomplete
        && expected.dropped_chunks == found.dropped_chunks
        && expected.input_recorded == found.input_recorded;
    if expected.kind == SessionKind::Shell {
        return common;
    }
    common
        && expected.bytes_out == found.bytes_out
        && expected.bytes_in == found.bytes_in
        && expected.command == found.command
        && expected.exit_status == found.exit_status
}

fn well_formed(manifest: &SessionManifest, found: &StoreProof) -> bool {
    if manifest.version != MANIFEST_VERSION {
        return false;
    }
    if manifest.chunks > 0 && manifest.raw_bytes > 0 && found.cast_sha256.is_none() {
        return false;
    }
    if manifest.incomplete {
        return true;
    }
    manifest.dropped_chunks == 0
        && (manifest.chunks == 0 || manifest.digest.is_some())
        && found.cast_bytes == manifest.raw_bytes
}

fn complete_with_other_chunks(manifest: &SessionManifest, delivered: Option<u64>) -> bool {
    !manifest.incomplete && delivered.is_some_and(|delivered| manifest.chunks != delivered)
}

pub fn resolve_existing(
    identity: &Identity,
    local: Option<&LocalProof<'_>>,
    found: &Result<Option<StoreProof>, RecordingStoreError>,
) -> Resolution {
    let found = match found {
        Ok(Some(found)) => found,
        Ok(None) => return Resolution::Nothing,
        Err(RecordingStoreError::InvalidManifest | RecordingStoreError::UnsafePath) => {
            return Resolution::Conflict(UNREADABLE_CONFLICT);
        }
        Err(_) => return Resolution::Retry,
    };
    let manifest = &found.manifest;
    if manifest.session_id != identity.session_id
        || manifest.node != identity.node
        || manifest.user != identity.user
        || identity.login.as_deref() != Some(manifest.login.as_str())
    {
        return Resolution::Conflict(IDENTITY_CONFLICT);
    }
    if found.cast_bytes > manifest.raw_bytes {
        return Resolution::Conflict(LENGTH_CONFLICT);
    }
    if !well_formed(manifest, found) {
        return Resolution::Conflict(STRUCTURE_CONFLICT);
    }
    let Some(local) = local else {
        return Resolution::Adopt;
    };
    if local.cast != found.cast().as_ref() {
        return Resolution::Conflict(CAST_CONFLICT);
    }
    match local.manifest {
        Some(expected)
            if agree(expected, manifest) || is_lost_acknowledgement(expected, manifest) =>
        {
            Resolution::Adopt
        }
        Some(_) => Resolution::Conflict(MANIFEST_CONFLICT),
        None if complete_with_other_chunks(manifest, local.chunks) => {
            Resolution::Conflict(MANIFEST_CONFLICT)
        }
        None => Resolution::Adopt,
    }
}
