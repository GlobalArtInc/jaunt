use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_audit::{
    Committed, RecordingKey, RecordingSink, RecordingStoreError, StagedRecording, cast_sha256,
    manifest_sha256, store_error_of,
};
use jaunt_proto::{
    RecordingAck, RecordingChunk, RecordingComplete, RecordingKind, RecordingManifest,
    RecordingReceipt, RecordingRefusal, RecordingState as WireState,
};
use jaunt_record::{
    AssembleError, Assembler, Chunk, MANIFEST_VERSION, SessionKind, SessionManifest, Verified,
    VerifyError,
};
use jaunt_store::{
    Recording, RecordingState, SessionState, StoreError, StoredRecording, UploadTarget,
};
use tokio::sync::OwnedMutexGuard;

use super::LATE_UPLOAD_SECS;
use super::audit::{self, Completed, Reason};
use super::uploads::{Admission, Created, Entry, FinishError, Slot, Upload, Uploads};
use crate::control::Control;

const OPEN_ATTEMPTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Refused {
        refusal: RecordingRefusal,
        reason: Reason,
    },
    Internal,
}

const fn refused(refusal: RecordingRefusal, reason: Reason) -> Failure {
    Failure::Refused { refusal, reason }
}

const fn closed() -> Failure {
    refused(RecordingRefusal::Closed, Reason::BadState)
}

const fn bad_chunk() -> Failure {
    refused(RecordingRefusal::BadChunk, Reason::BadChunk)
}

const fn not_recordable() -> Failure {
    refused(RecordingRefusal::NotRecordable, Reason::BadState)
}

const fn conflict() -> Failure {
    refused(RecordingRefusal::Conflict, Reason::Conflict)
}

fn internal(operation: &'static str) -> impl FnOnce(StoreError) -> Failure {
    move |err| {
        tracing::error!(target: "jaunt::control", error = %err, operation, "a recording store operation failed");
        Failure::Internal
    }
}

pub(crate) fn report(
    control: &Control,
    node_id: &str,
    session_id: Option<&str>,
    failure: &Failure,
) {
    if let Failure::Refused { reason, .. } = failure {
        reject(control, node_id, session_id, *reason);
    }
}

pub(crate) fn reject(control: &Control, node_id: &str, session_id: Option<&str>, reason: Reason) {
    let now = control.now().map_or(0, |moment| moment.secs);
    let admitted = if reason == Reason::DiskFull {
        let admitted = match control.recordings.as_ref() {
            Some(uploads) => uploads.report_disk_full(now),
            None => Some(0),
        };
        if admitted.is_some() {
            tracing::warn!(
                target: "jaunt::control",
                "the recording storage is below its free space reserve: recordings are refused"
            );
        }
        admitted
    } else {
        control
            .recording_rejections
            .admit(node_id, session_id, reason, now)
    };
    if let Some(suppressed) = admitted {
        audit::rejected(node_id, session_id, reason, suppressed);
    }
}

pub(crate) async fn chunk(
    control: Control,
    node_id: String,
    session_id: String,
    body: RecordingChunk,
) -> Result<RecordingAck, Failure> {
    let result = chunk_flow(&control, &node_id, &session_id, body).await;
    if let Err(failure) = &result {
        report(&control, &node_id, Some(&session_id), failure);
    }
    result
}

pub(crate) async fn complete(
    control: Control,
    node_id: String,
    session_id: String,
    body: RecordingComplete,
) -> Result<RecordingReceipt, Failure> {
    let result = complete_flow(&control, &node_id, &session_id, body).await;
    if let Err(failure) = &result {
        report(&control, &node_id, Some(&session_id), failure);
    }
    result
}

fn enabled(control: &Control) -> Result<&Uploads, Failure> {
    control
        .recordings
        .as_ref()
        .ok_or(refused(RecordingRefusal::Disabled, Reason::Disabled))
}

fn now_secs(control: &Control) -> Result<i64, Failure> {
    control.now().map(|moment| moment.secs).ok_or_else(|| {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        Failure::Internal
    })
}

async fn load_target(
    control: &Control,
    node_id: &str,
    session_id: &str,
    now: i64,
) -> Result<UploadTarget, Failure> {
    let Some(target) = control
        .store
        .recordings()
        .upload_target(session_id)
        .await
        .map_err(internal("loading the session of a recording"))?
    else {
        return Err(refused(
            RecordingRefusal::SessionUnknown,
            Reason::UnknownSession,
        ));
    };
    if target.node_id != node_id {
        return Err(refused(RecordingRefusal::SessionUnknown, Reason::WrongNode));
    }
    let recordable = match target.state {
        SessionState::Routed => false,
        SessionState::Active => true,
        SessionState::Ended => target
            .ended_at
            .is_some_and(|ended| now.saturating_sub(ended) <= LATE_UPLOAD_SECS),
    };
    if !recordable || target.authorized_at.is_none() {
        return Err(not_recordable());
    }
    Ok(target)
}

async fn chunk_flow(
    control: &Control,
    node_id: &str,
    session_id: &str,
    body: RecordingChunk,
) -> Result<RecordingAck, Failure> {
    let uploads = enabled(control)?;
    let now = now_secs(control)?;
    let target = load_target(control, node_id, session_id, now).await?;
    if target.pty == Some(false) {
        return Err(not_recordable());
    }
    let Ok(compressed) = STANDARD.decode(body.data.as_bytes()) else {
        close_session(control, uploads, &target, now).await;
        return Err(bad_chunk());
    };
    let chunk = Chunk {
        session_id: session_id.to_owned(),
        seq: body.seq,
        raw_len: body.raw_len,
        compressed,
        sha256: body.sha256,
        is_last: body.is_last,
    };
    let (entry, mut guard) = open_upload(control, uploads, &target, now).await?;
    entry.touch(now);
    let Slot::Open(upload) = std::mem::replace(&mut *guard, Slot::Opening) else {
        *guard = Slot::Gone;
        uploads.remove(&entry, 0);
        return Err(Failure::Internal);
    };
    let reserved = upload.pending_cost(chunk.seq, chunk.compressed.len());
    let session_budget =
        u64::try_from(uploads.limits().chunk.max_pending_bytes).unwrap_or(u64::MAX);
    if upload.pending().saturating_add(reserved) > session_budget {
        close_upload(control, uploads, &entry, guard, upload, now).await;
        return Err(refused(RecordingRefusal::TooLarge, Reason::Limit));
    }
    if uploads.reserve(node_id, reserved) == Admission::TooMany {
        *guard = Slot::Open(upload);
        return Err(refused(RecordingRefusal::TooMany, Reason::Limit));
    }
    let seq = chunk.seq;
    let pending_before = upload.pending();
    let joined = tokio::task::spawn_blocking(move || {
        let mut upload = upload;
        let result = upload.accept(&chunk);
        (upload, result)
    })
    .await;
    let Ok((mut upload, result)) = joined else {
        uploads.release(node_id, reserved);
        lost_upload(control, uploads, &entry, guard, pending_before, now).await;
        return Err(Failure::Internal);
    };
    match result {
        Ok(jaunt_record::Accepted::New) => uploads.record_new(node_id, &mut upload, seq, reserved),
        Ok(jaunt_record::Accepted::Duplicate) => uploads.release(node_id, reserved),
        Err(error) => {
            uploads.release(node_id, reserved);
            let failure = assemble_failure(&error);
            close_upload(control, uploads, &entry, guard, upload, now).await;
            return Err(failure);
        }
    }
    if upload.unpersisted_progress()
        && let Some(prefix_sha256) = upload.delivered_sha256()
    {
        let delivered_chunks = upload.delivered_chunks();
        let progress = control
            .store
            .recordings()
            .record_progress(
                session_id,
                delivered_chunks,
                upload.delivered_bytes(),
                &prefix_sha256,
            )
            .await;
        match progress {
            Ok(true) => upload.mark_persisted(delivered_chunks),
            Ok(false) => {
                tracing::warn!(target: "jaunt::control", session_id, "an upload found its table row no longer receiving");
                close_upload(control, uploads, &entry, guard, upload, now).await;
                return Err(closed());
            }
            Err(err) => {
                tracing::error!(target: "jaunt::control", error = %err, "recording the upload progress failed");
                *guard = Slot::Open(upload);
                return Err(Failure::Internal);
            }
        }
    }
    let ack = RecordingAck {
        acked_through: upload.acked_through(),
    };
    *guard = Slot::Open(upload);
    Ok(ack)
}

async fn complete_flow(
    control: &Control,
    node_id: &str,
    session_id: &str,
    body: RecordingComplete,
) -> Result<RecordingReceipt, Failure> {
    let uploads = enabled(control)?;
    let now = now_secs(control)?;
    let target = load_target(control, node_id, session_id, now).await?;
    let manifest = session_manifest(body.manifest);
    let same_identity = manifest.session_id == target.session_id
        && manifest.node == target.node_id
        && manifest.user == target.user_id
        && target.login.as_deref() == Some(manifest.login.as_str());
    if !same_identity {
        return Err(conflict());
    }
    let manifest_sha = manifest_sha256(&manifest).map_err(|_| Failure::Internal)?;
    if let Some(receipt) = stored_outcome(target.recording.as_ref(), &manifest_sha)? {
        return Ok(receipt);
    }
    if manifest
        .digest
        .as_deref()
        .is_some_and(|digest| !is_sha256_hex(digest))
    {
        close_session(control, uploads, &target, now).await;
        return Err(bad_chunk());
    }
    let expects_cast = manifest.kind == SessionKind::Shell;
    let input_refused = manifest.input_recorded && !target.record_input.unwrap_or(false);
    let cast_refused = expects_cast && !target.pty.unwrap_or(true);
    if input_refused || cast_refused {
        close_session(control, uploads, &target, now).await;
        return Err(not_recordable());
    }
    let (entry, mut guard) = match open_upload(control, uploads, &target, now).await {
        Ok(opened) => opened,
        Err(failure) => {
            return finished_elsewhere(control, session_id, &manifest_sha, failure).await;
        }
    };
    entry.touch(now);
    let Slot::Open(upload) = std::mem::replace(&mut *guard, Slot::Opening) else {
        *guard = Slot::Gone;
        uploads.remove(&entry, 0);
        return Err(Failure::Internal);
    };
    if !expects_cast && upload.received > 0 {
        close_upload(control, uploads, &entry, guard, upload, now).await;
        return Err(not_recordable());
    }
    let pending_before = upload.pending();
    let joined = tokio::task::spawn_blocking(move || {
        let mut upload = upload;
        let result = upload.finish(&manifest, expects_cast);
        (upload, manifest, result)
    })
    .await;
    let Ok((upload, manifest, result)) = joined else {
        lost_upload(control, uploads, &entry, guard, pending_before, now).await;
        return Err(Failure::Internal);
    };
    let (verified, committed) = match result {
        Ok(done) => done,
        Err(error) => {
            let failure = match &error {
                FinishError::Verify(error) => verify_failure(error),
                FinishError::Commit(error) => storage_failure(error),
            };
            close_upload(control, uploads, &entry, guard, upload, now).await;
            return Err(failure);
        }
    };
    let marked = mark_stored(control, node_id, &manifest, &verified, &committed, now).await;
    *guard = Slot::Closed;
    uploads.remove(&entry, upload.pending());
    drop(guard);
    drop(upload);
    match marked {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(
                target: "jaunt::control",
                session_id,
                "a stored recording found its table row no longer receiving"
            );
            return Err(Failure::Internal);
        }
        Err(err) => return Err(internal("marking a recording stored")(err)),
    }
    audit::completed(&Completed {
        session_id,
        node_id,
        chunks: verified.received_chunks,
        raw_bytes: verified.raw_bytes,
        incomplete: verified.incomplete,
        input_recorded: manifest.input_recorded,
    });
    let state = match reconcile_with_session(control, session_id, node_id).await {
        Some(state) => state,
        None => wire_state(verified.incomplete),
    };
    Ok(RecordingReceipt {
        state,
        chunks: verified.received_chunks,
    })
}

async fn mark_stored(
    control: &Control,
    node_id: &str,
    manifest: &SessionManifest,
    verified: &Verified,
    committed: &Committed,
    now: i64,
) -> Result<bool, StoreError> {
    let stored = StoredRecording {
        session_id: &manifest.session_id,
        node_id,
        chunks: verified.received_chunks,
        raw_bytes: verified.raw_bytes,
        digest: manifest.digest.as_deref(),
        input_recorded: manifest.input_recorded,
        dropped_chunks: manifest.dropped_chunks,
        location: &committed.location,
        cast_sha256: committed.cast_sha256.as_deref(),
        manifest_sha256: &committed.manifest_sha256,
        now,
    };
    let recordings = control.store.recordings();
    if verified.incomplete {
        recordings.mark_incomplete(&stored).await
    } else {
        recordings.mark_complete(&stored).await
    }
}

async fn reconcile_with_session(
    control: &Control,
    session_id: &str,
    node_id: &str,
) -> Option<WireState> {
    let session = match control.store.sessions().get(session_id).await {
        Ok(session) => session?,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading a session to reconcile its recording failed");
            return None;
        }
    };
    let flag = session.recording_incomplete?;
    reconcile(control, session_id, node_id, flag).await
}

pub(crate) async fn reconcile(
    control: &Control,
    session_id: &str,
    node_id: &str,
    session_incomplete: bool,
) -> Option<WireState> {
    let reconciled = match control
        .store
        .recordings()
        .reconcile(session_id, session_incomplete)
        .await
    {
        Ok(reconciled) => reconciled?,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reconciling a recording with its session failed");
            return None;
        }
    };
    if reconciled.manifest_incomplete != reconciled.session_incomplete {
        audit::mismatch(
            node_id,
            session_id,
            reconciled.manifest_incomplete,
            reconciled.session_incomplete,
        );
    }
    Some(wire_state(reconciled.state == RecordingState::Incomplete))
}

fn wire_state(incomplete: bool) -> WireState {
    if incomplete {
        WireState::Incomplete
    } else {
        WireState::Complete
    }
}

fn stored_outcome(
    recording: Option<&Recording>,
    manifest_sha: &str,
) -> Result<Option<RecordingReceipt>, Failure> {
    let Some(recording) = recording else {
        return Ok(None);
    };
    if recording.salvaged {
        return Err(closed());
    }
    match recording.state {
        RecordingState::Receiving => Ok(None),
        RecordingState::Failed => Err(closed()),
        RecordingState::Complete | RecordingState::Incomplete => {
            if recording.manifest_sha256.as_deref() == Some(manifest_sha) {
                Ok(Some(RecordingReceipt {
                    state: wire_state(recording.state == RecordingState::Incomplete),
                    chunks: recording.chunks,
                }))
            } else {
                Err(conflict())
            }
        }
    }
}

async fn finished_elsewhere(
    control: &Control,
    session_id: &str,
    manifest_sha: &str,
    failure: Failure,
) -> Result<RecordingReceipt, Failure> {
    if failure != closed() {
        return Err(failure);
    }
    let recording = control
        .store
        .recordings()
        .get(session_id)
        .await
        .map_err(internal("loading a recording"))?;
    match stored_outcome(recording.as_ref(), manifest_sha)? {
        Some(receipt) => Ok(receipt),
        None => Err(failure),
    }
}

async fn open_upload(
    control: &Control,
    uploads: &Uploads,
    target: &UploadTarget,
    now: i64,
) -> Result<(Arc<Entry>, OwnedMutexGuard<Slot>), Failure> {
    for _ in 0..OPEN_ATTEMPTS {
        if let Some(entry) = uploads.find(&target.session_id) {
            let guard = entry.lock().await;
            match &*guard {
                Slot::Open(_) => return Ok((entry, guard)),
                Slot::Closed => return Err(closed()),
                Slot::Opening | Slot::Gone => continue,
            }
        }
        let row = control
            .store
            .recordings()
            .get(&target.session_id)
            .await
            .map_err(internal("loading a recording"))?;
        match row.map(|recording| recording.state) {
            None => {}
            Some(RecordingState::Receiving) => {
                if uploads.find(&target.session_id).is_some() {
                    continue;
                }
                fail_or_adopt(control, uploads, target, now).await;
                return Err(closed());
            }
            Some(_) => return Err(closed()),
        }
        match uploads.create(&target.session_id, &target.node_id, now) {
            Created::Exists => continue,
            Created::Refused => return Err(refused(RecordingRefusal::TooMany, Reason::Limit)),
            Created::Fresh(entry, mut guard) => {
                return match initialize(control, uploads, target, now).await {
                    Ok(upload) => {
                        *guard = Slot::Open(Box::new(upload));
                        Ok((entry, guard))
                    }
                    Err(failure) => {
                        *guard = Slot::Gone;
                        uploads.remove(&entry, 0);
                        Err(failure)
                    }
                };
            }
        }
    }
    tracing::error!(target: "jaunt::control", "a recording upload could not be opened after several attempts");
    Err(Failure::Internal)
}

async fn initialize(
    control: &Control,
    uploads: &Uploads,
    target: &UploadTarget,
    now: i64,
) -> Result<Upload, Failure> {
    let authorized_at = target.authorized_at.ok_or(not_recordable())?;
    let key = RecordingKey::new(&target.session_id, authorized_at).map_err(|err| {
        tracing::error!(target: "jaunt::control", error = %err, "a session cannot name a recording");
        Failure::Internal
    })?;
    let sink = uploads.sink();
    let begun = tokio::task::spawn_blocking(move || sink.begin(&key))
        .await
        .map_err(|_| Failure::Internal)?;
    let staged = begun.map_err(|err| storage_failure(&err))?;
    match control
        .store
        .recordings()
        .begin(&target.session_id, &target.node_id, now)
        .await
    {
        Ok(row) if row.state == RecordingState::Receiving => Ok(Upload::new(
            Assembler::new(target.session_id.clone(), uploads.limits().chunk),
            staged,
        )),
        Ok(_) => {
            abort_staged(staged).await;
            Err(closed())
        }
        Err(err) => {
            abort_staged(staged).await;
            Err(internal("beginning a recording")(err))
        }
    }
}

async fn abort_staged(staged: Box<dyn StagedRecording>) {
    match tokio::task::spawn_blocking(move || staged.abort()).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            tracing::warn!(target: "jaunt::control", error = %err, "removing a staged recording failed");
        }
        Err(_) => {
            tracing::warn!(target: "jaunt::control", "removing a staged recording panicked");
        }
    }
}

async fn mark_failed(control: &Control, session_id: &str, now: i64) {
    if let Err(err) = control
        .store
        .recordings()
        .mark_failed(session_id, now)
        .await
    {
        tracing::error!(target: "jaunt::control", error = %err, "marking a recording failed did not succeed");
    }
}

async fn close_upload(
    control: &Control,
    uploads: &Uploads,
    entry: &Entry,
    mut guard: OwnedMutexGuard<Slot>,
    mut upload: Box<Upload>,
    now: i64,
) {
    *guard = Slot::Closed;
    uploads.remove(entry, upload.pending());
    if let Some(staged) = upload.staged.take() {
        abort_staged(staged).await;
    }
    drop(upload);
    mark_failed(control, &entry.session_id, now).await;
}

async fn lost_upload(
    control: &Control,
    uploads: &Uploads,
    entry: &Entry,
    mut guard: OwnedMutexGuard<Slot>,
    pending: u64,
    now: i64,
) {
    tracing::error!(target: "jaunt::control", session_id = %entry.session_id, "a recording worker panicked: the upload is closed");
    *guard = Slot::Closed;
    uploads.remove(entry, pending);
    mark_failed(control, &entry.session_id, now).await;
}

async fn close_session(control: &Control, uploads: &Uploads, target: &UploadTarget, now: i64) {
    if let Some(entry) = uploads.find(&target.session_id) {
        let mut guard = entry.lock().await;
        match std::mem::replace(&mut *guard, Slot::Closed) {
            Slot::Open(upload) => {
                close_upload(control, uploads, &entry, guard, upload, now).await;
                return;
            }
            other => *guard = other,
        }
    }
    match control
        .store
        .recordings()
        .begin(&target.session_id, &target.node_id, now)
        .await
    {
        Ok(row) if row.state == RecordingState::Receiving => {
            fail_or_adopt(control, uploads, target, now).await;
        }
        Ok(_) => {}
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "closing a refused recording failed");
        }
    }
}

pub(crate) async fn sweep(control: &Control) -> usize {
    let Some(uploads) = control.recordings.as_ref() else {
        return 0;
    };
    let Some(now) = control.now().map(|moment| moment.secs) else {
        return 0;
    };
    let idle_secs = i64::try_from(uploads.limits().idle_timeout.as_secs()).unwrap_or(i64::MAX);
    let mut expired = 0;
    for (entry, mut guard) in uploads.candidates_idle_since(now) {
        let target = match control
            .store
            .recordings()
            .upload_target(&entry.session_id)
            .await
        {
            Ok(target) => target,
            Err(err) => {
                tracing::error!(target: "jaunt::control", error = %err, "loading the session of an idle upload failed");
                continue;
            }
        };
        let live = target
            .as_ref()
            .is_some_and(|target| target.state == SessionState::Active);
        let quiet_since = target
            .as_ref()
            .and_then(|target| target.ended_at)
            .map_or(entry.last_seen(), |ended| ended.max(entry.last_seen()));
        if live || quiet_since.saturating_add(idle_secs) > now {
            continue;
        }
        expired += 1;
        match std::mem::replace(&mut *guard, Slot::Closed) {
            Slot::Open(upload) => {
                expire(
                    control,
                    uploads,
                    &entry,
                    guard,
                    upload,
                    target.as_ref(),
                    now,
                )
                .await;
            }
            _ => uploads.remove(&entry, 0),
        }
    }
    expired
}

async fn expire(
    control: &Control,
    uploads: &Uploads,
    entry: &Entry,
    guard: OwnedMutexGuard<Slot>,
    mut upload: Box<Upload>,
    target: Option<&UploadTarget>,
    now: i64,
) {
    let delivered = upload.delivered_chunks();
    if let (Some(target), true) = (target, delivered > 0)
        && let Some(staged) = upload.staged.take()
    {
        let pending = upload.pending();
        drop(upload);
        salvage(control, target, staged, delivered, now).await;
        uploads.remove(entry, pending);
        drop(guard);
        return;
    }
    close_upload(control, uploads, entry, guard, upload, now).await;
    reject(
        control,
        &entry.node_id,
        Some(&entry.session_id),
        Reason::Limit,
    );
}

fn salvaged_manifest(target: &UploadTarget, chunks: u64, raw_bytes: u64) -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: target.session_id.clone(),
        kind: SessionKind::Shell,
        node: target.node_id.clone(),
        user: target.user_id.clone(),
        login: target.login.clone().unwrap_or_default(),
        started_at: target
            .authorized_at
            .and_then(|secs| u64::try_from(secs).ok())
            .unwrap_or(0),
        ended_at: target.ended_at.and_then(|secs| u64::try_from(secs).ok()),
        exit_status: None,
        command: None,
        bytes_out: 0,
        bytes_in: 0,
        input_recorded: target.record_input.unwrap_or(false),
        chunks,
        raw_bytes,
        incomplete: true,
        dropped_chunks: 0,
        digest: None,
    }
}

async fn salvage(
    control: &Control,
    target: &UploadTarget,
    staged: Box<dyn StagedRecording>,
    chunks: u64,
    now: i64,
) -> bool {
    let manifest = salvaged_manifest(target, chunks, staged.written());
    let joined = tokio::task::spawn_blocking(move || {
        let committed = staged.commit(&manifest);
        (manifest, committed)
    })
    .await;
    let (manifest, committed) = match joined {
        Ok((manifest, Ok(committed))) => (manifest, committed),
        Ok((_, Err(err))) => {
            tracing::error!(target: "jaunt::control", error = %err, "storing the delivered part of a recording failed");
            mark_failed(control, &target.session_id, now).await;
            return false;
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "storing the delivered part of a recording panicked");
            mark_failed(control, &target.session_id, now).await;
            return false;
        }
    };
    let stored = StoredRecording {
        session_id: &target.session_id,
        node_id: &target.node_id,
        chunks,
        raw_bytes: manifest.raw_bytes,
        digest: None,
        input_recorded: manifest.input_recorded,
        dropped_chunks: 0,
        location: &committed.location,
        cast_sha256: committed.cast_sha256.as_deref(),
        manifest_sha256: &committed.manifest_sha256,
        now,
    };
    match control.store.recordings().mark_salvaged(&stored).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(target: "jaunt::control", session_id = %target.session_id, "a salvaged recording found its table row no longer receiving");
            return false;
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "marking a salvaged recording failed");
            return false;
        }
    }
    audit::completed(&Completed {
        session_id: &target.session_id,
        node_id: &target.node_id,
        chunks,
        raw_bytes: manifest.raw_bytes,
        incomplete: true,
        input_recorded: manifest.input_recorded,
    });
    reconcile_with_session(control, &target.session_id, &target.node_id).await;
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Adoption {
    Adopted,
    Absent,
    Refused,
    RowMoved,
    StoreFailed,
}

async fn fail_or_adopt(control: &Control, uploads: &Uploads, target: &UploadTarget, now: i64) {
    match adopt(control, uploads, target, now).await {
        Adoption::Adopted | Adoption::RowMoved | Adoption::StoreFailed => {}
        Adoption::Absent | Adoption::Refused => {
            mark_failed(control, &target.session_id, now).await;
        }
    }
}

struct Found {
    manifest: SessionManifest,
    manifest_sha256: String,
    cast_bytes: u64,
    cast_sha256: Option<String>,
}

fn read_stored(
    sink: &dyn RecordingSink,
    key: &RecordingKey,
) -> Result<Option<Found>, RecordingStoreError> {
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
    Ok(Some(Found {
        manifest: stored.manifest,
        manifest_sha256: stored.manifest_sha256,
        cast_bytes,
        cast_sha256,
    }))
}

async fn adopt(control: &Control, uploads: &Uploads, target: &UploadTarget, now: i64) -> Adoption {
    let Some(key) = target
        .authorized_at
        .and_then(|started| RecordingKey::new(&target.session_id, started).ok())
    else {
        return Adoption::Absent;
    };
    let location = key.location();
    let sink = uploads.sink();
    let found = match tokio::task::spawn_blocking(move || read_stored(sink.as_ref(), &key)).await {
        Ok(Ok(Some(found))) => found,
        Ok(Ok(None)) => return Adoption::Absent,
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading a stored recording to adopt it failed");
            return Adoption::Refused;
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "reading a stored recording to adopt it panicked");
            return Adoption::Refused;
        }
    };
    let manifest = &found.manifest;
    let belongs = manifest.node == target.node_id
        && manifest.user == target.user_id
        && target.login.as_deref() == Some(manifest.login.as_str())
        && found.cast_bytes <= manifest.raw_bytes;
    if !belongs {
        tracing::error!(
            target: "jaunt::control",
            session_id = %target.session_id,
            "a stored manifest does not match its session or its cast: the files are kept and the recording is marked failed"
        );
        return Adoption::Refused;
    }
    let stored = StoredRecording {
        session_id: &target.session_id,
        node_id: &target.node_id,
        chunks: manifest.chunks.saturating_sub(manifest.dropped_chunks),
        raw_bytes: found.cast_bytes,
        digest: manifest.digest.as_deref(),
        input_recorded: manifest.input_recorded,
        dropped_chunks: manifest.dropped_chunks,
        location: &location,
        cast_sha256: found.cast_sha256.as_deref(),
        manifest_sha256: &found.manifest_sha256,
        now,
    };
    let recordings = control.store.recordings();
    let marked = if manifest.incomplete && manifest.digest.is_none() && manifest.chunks > 0 {
        recordings.mark_salvaged(&stored).await
    } else if manifest.incomplete {
        recordings.mark_incomplete(&stored).await
    } else {
        recordings.mark_complete(&stored).await
    };
    match marked {
        Ok(true) => {}
        Ok(false) => return Adoption::RowMoved,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "adopting a stored recording failed");
            return Adoption::StoreFailed;
        }
    }
    tracing::warn!(target: "jaunt::control", session_id = %target.session_id, "a stored recording whose table row was still receiving was adopted");
    audit::completed(&Completed {
        session_id: &target.session_id,
        node_id: &target.node_id,
        chunks: stored.chunks,
        raw_bytes: found.cast_bytes,
        incomplete: manifest.incomplete,
        input_recorded: manifest.input_recorded,
    });
    reconcile_with_session(control, &target.session_id, &target.node_id).await;
    Adoption::Adopted
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveredRecordings {
    pub adopted: u64,
    pub salvaged: u64,
    pub failed: u64,
}

pub(crate) async fn recover(control: &Control) -> Result<RecoveredRecordings, StoreError> {
    let mut recovered = RecoveredRecordings::default();
    let Some(uploads) = control.recordings.as_ref() else {
        return Ok(recovered);
    };
    let Some(now) = control.now().map(|moment| moment.secs) else {
        return Ok(recovered);
    };
    let recordings = control.store.recordings();
    for row in recordings.list_receiving().await? {
        if uploads.find(&row.session_id).is_some() {
            continue;
        }
        let target = recordings.upload_target(&row.session_id).await?;
        if let Some(target) = &target {
            match adopt(control, uploads, target, now).await {
                Adoption::Adopted => {
                    recovered.adopted += 1;
                    continue;
                }
                Adoption::Refused => {
                    mark_failed(control, &row.session_id, now).await;
                    recovered.failed += 1;
                    continue;
                }
                Adoption::RowMoved | Adoption::StoreFailed => {
                    tracing::warn!(target: "jaunt::control", session_id = %row.session_id, "an interrupted recording could not be adopted now: it stays receiving");
                    continue;
                }
                Adoption::Absent => {}
            }
        }
        let resumed = match (&target, &row.progress_sha256) {
            (Some(target), Some(prefix)) if row.chunks > 0 => {
                resume(uploads, target, row.raw_bytes, prefix).await
            }
            _ => None,
        };
        let salvaged = match (target, resumed) {
            (Some(target), Some(staged)) => {
                salvage(control, &target, staged, row.chunks, now).await
            }
            _ => {
                mark_failed(control, &row.session_id, now).await;
                false
            }
        };
        if salvaged {
            recovered.salvaged += 1;
        } else {
            recovered.failed += 1;
        }
    }
    Ok(recovered)
}

async fn resume(
    uploads: &Uploads,
    target: &UploadTarget,
    raw_bytes: u64,
    prefix_sha256: &str,
) -> Option<Box<dyn StagedRecording>> {
    let key = RecordingKey::new(&target.session_id, target.authorized_at?).ok()?;
    let sink = uploads.sink();
    let prefix_sha256 = prefix_sha256.to_owned();
    match tokio::task::spawn_blocking(move || sink.resume(&key, raw_bytes, &prefix_sha256)).await {
        Ok(Ok(staged)) => staged,
        Ok(Err(err)) => {
            tracing::error!(target: "jaunt::control", error = %err, "resuming an interrupted recording failed");
            None
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "resuming an interrupted recording panicked");
            None
        }
    }
}

fn assemble_failure(error: &AssembleError) -> Failure {
    match error {
        AssembleError::CompressedTooLarge
        | AssembleError::RawTooLarge
        | AssembleError::SeqLimit
        | AssembleError::TotalRawLimit
        | AssembleError::PendingLimit => refused(RecordingRefusal::TooLarge, Reason::Limit),
        AssembleError::Conflict { .. } => conflict(),
        AssembleError::Sink(sink) => {
            store_error_of(sink).map_or(Failure::Internal, storage_failure)
        }
        AssembleError::SessionMismatch
        | AssembleError::ChecksumMismatch
        | AssembleError::Decompress
        | AssembleError::RawLenMismatch
        | AssembleError::AfterLast { .. }
        | AssembleError::LastNotFinal { .. }
        | AssembleError::ConflictingLast => bad_chunk(),
    }
}

fn verify_failure(error: &VerifyError) -> Failure {
    match error {
        VerifyError::Sink(sink) => store_error_of(sink).map_or(Failure::Internal, storage_failure),
        VerifyError::SessionMismatch => conflict(),
        VerifyError::UnsupportedVersion(_)
        | VerifyError::Gap { .. }
        | VerifyError::MissingLast
        | VerifyError::InconsistentManifest
        | VerifyError::ChunkCountMismatch
        | VerifyError::RawBytesMismatch
        | VerifyError::DigestMismatch
        | VerifyError::Decompress
        | VerifyError::NoRecording
        | VerifyError::MetadataOnlyMismatch => bad_chunk(),
    }
}

fn storage_failure(error: &RecordingStoreError) -> Failure {
    match error {
        RecordingStoreError::DiskFull => {
            refused(RecordingRefusal::InsufficientStorage, Reason::DiskFull)
        }
        RecordingStoreError::TooLarge => refused(RecordingRefusal::TooLarge, Reason::Limit),
        other => {
            tracing::error!(target: "jaunt::control", error = %other, "the recording storage failed");
            Failure::Internal
        }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn session_manifest(manifest: RecordingManifest) -> SessionManifest {
    SessionManifest {
        version: manifest.version,
        session_id: manifest.session_id,
        kind: match manifest.kind {
            RecordingKind::Shell => SessionKind::Shell,
            RecordingKind::Exec => SessionKind::Exec,
            RecordingKind::Sftp => SessionKind::Sftp,
        },
        node: manifest.node,
        user: manifest.user,
        login: manifest.login,
        started_at: manifest.started_at,
        ended_at: manifest.ended_at,
        exit_status: manifest.exit_status,
        command: manifest.command,
        bytes_out: manifest.bytes_out,
        bytes_in: manifest.bytes_in,
        input_recorded: manifest.input_recorded,
        chunks: manifest.chunks,
        raw_bytes: manifest.raw_bytes,
        incomplete: manifest.incomplete,
        dropped_chunks: manifest.dropped_chunks,
        digest: manifest.digest,
    }
}

#[cfg(test)]
mod tests {
    use jaunt_proto::{RecordingKind, RecordingManifest};
    use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};

    use super::session_manifest;

    #[test]
    fn the_transport_manifest_has_the_shape_of_the_recorder_manifest() {
        let manifest = SessionManifest {
            version: MANIFEST_VERSION,
            session_id: "s".to_owned(),
            kind: SessionKind::Sftp,
            node: "n".to_owned(),
            user: "u".to_owned(),
            login: "l".to_owned(),
            started_at: 1,
            ended_at: Some(2),
            exit_status: Some(3),
            command: Some("c".to_owned()),
            bytes_out: 4,
            bytes_in: 5,
            input_recorded: true,
            chunks: 6,
            raw_bytes: 7,
            incomplete: true,
            dropped_chunks: 8,
            digest: Some("d".to_owned()),
        };
        let wire: RecordingManifest =
            serde_json::from_value(serde_json::to_value(&manifest).unwrap()).unwrap();
        assert_eq!(wire.kind, RecordingKind::Sftp);
        assert_eq!(
            serde_json::to_value(&wire).unwrap(),
            serde_json::to_value(&manifest).unwrap()
        );
        assert_eq!(session_manifest(wire), manifest);
    }
}
