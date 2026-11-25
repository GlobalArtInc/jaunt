#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Reason {
    UnknownSession,
    WrongNode,
    BadState,
    BadChunk,
    Conflict,
    Limit,
    DiskFull,
    Disabled,
}

impl Reason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Reason::UnknownSession => "unknown_session",
            Reason::WrongNode => "wrong_node",
            Reason::BadState => "bad_state",
            Reason::BadChunk => "bad_chunk",
            Reason::Conflict => "conflict",
            Reason::Limit => "limit",
            Reason::DiskFull => "disk_full",
            Reason::Disabled => "disabled",
        }
    }
}

pub(crate) struct Completed<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) chunks: u64,
    pub(crate) raw_bytes: u64,
    pub(crate) incomplete: bool,
    pub(crate) input_recorded: bool,
}

pub(crate) fn completed(event: &Completed<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "recording.completed",
        session_id = event.session_id,
        node_id = event.node_id,
        chunks = event.chunks,
        raw_bytes = event.raw_bytes,
        incomplete = event.incomplete,
        input_recorded = event.input_recorded
    );
}

pub(crate) fn rejected(node_id: &str, session_id: Option<&str>, reason: Reason, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "recording.rejected",
        node_id,
        session_id,
        reason = reason.as_str(),
        suppressed
    );
}

pub(crate) fn mismatch(
    node_id: &str,
    session_id: &str,
    manifest_incomplete: bool,
    session_incomplete: bool,
) {
    tracing::info!(
        target: "jaunt::audit",
        event = "recording.mismatch",
        node_id,
        session_id,
        manifest_incomplete,
        session_incomplete
    );
}
