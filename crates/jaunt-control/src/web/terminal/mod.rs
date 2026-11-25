mod audit;
mod live;
mod open;
mod protocol;
mod run;
mod tickets;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_proto::BoxFuture;
use jaunt_ssh::{EphemeralKey, ForwardRefusal, JumpError, TunnelStream};
use tokio_util::sync::CancellationToken;

pub(crate) use self::live::{End, LiveTerminals};
pub(crate) use self::open::{open, targets, ticket};

pub const DEFAULT_MAX_TERMINALS_PER_USER: usize = 4;
pub const DEFAULT_MAX_TERMINALS: usize = 64;
pub const DEFAULT_TERMINAL_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_MAX_TERMINAL_TICKETS: usize = 1024;
pub const WEB_CERTIFICATE_VALIDITY: Duration = Duration::from_secs(120);
pub const TERMINAL_SUBPROTOCOL: &str = "jaunt-terminal.v1";
pub const TERMINAL_TICKET_PREFIX: &str = "jaunt-ticket.";
pub const TERMINAL_TICKET_TTL_SECS: i64 = 30;
pub const TERMINAL_MAX_FRAME_BYTES: usize = 64 * 1024;
pub const TERMINAL_PING_INTERVAL: Duration = Duration::from_secs(20);
pub const TERMINAL_DEAD_PEER_TIMEOUT: Duration = Duration::from_secs(60);
pub const TERMINAL_WEDGE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebTerminalSettings {
    pub max_per_user: usize,
    pub max_total: usize,
    pub idle_timeout: Duration,
    pub max_tickets: usize,
}

impl Default for WebTerminalSettings {
    fn default() -> Self {
        Self {
            max_per_user: DEFAULT_MAX_TERMINALS_PER_USER,
            max_total: DEFAULT_MAX_TERMINALS,
            idle_timeout: DEFAULT_TERMINAL_IDLE_TIMEOUT,
            max_tickets: DEFAULT_MAX_TERMINAL_TICKETS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEvent {
    Routed { session_id: String },
    Refused(ForwardRefusal),
}

pub type GateEvents = Arc<dyn Fn(GateEvent) + Send + Sync>;

pub struct GateRequest {
    pub client_addr: SocketAddr,
    pub shutdown: CancellationToken,
    pub events: GateEvents,
}

pub struct GateLink {
    pub stream: Box<dyn TunnelStream>,
    pub serve: BoxFuture<'static, ()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateRefusal {
    #[error("the gate has no room for another connection")]
    Busy,
    #[error("the client address is over the gate limits")]
    Limited,
}

pub trait TerminalGate: Send + Sync + 'static {
    fn host_name(&self) -> String;

    fn connect(&self, request: GateRequest) -> Result<GateLink, GateRefusal>;
}

#[cfg(feature = "test-support")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebTerminalCounters {
    pub open: usize,
    pub max_pending_output: u64,
    pub max_pending_input: u64,
    pub max_node_ahead: u64,
    pub pings: u64,
}

pub(crate) type KeySource = Arc<dyn Fn() -> Result<EphemeralKey, JumpError> + Send + Sync>;

pub(crate) struct Installed {
    pub(crate) gate: Arc<dyn TerminalGate>,
    pub(crate) settings: WebTerminalSettings,
    pub(crate) tickets: tickets::TicketTable,
}

#[derive(Default)]
pub(crate) struct Counters {
    max_pending_output: AtomicU64,
    max_pending_input: AtomicU64,
    max_node_ahead: AtomicU64,
    pings: AtomicU64,
}

impl Counters {
    pub(crate) fn pending_output(&self, pending: u64) {
        self.max_pending_output
            .fetch_max(pending, Ordering::Relaxed);
    }

    pub(crate) fn pending_input(&self, pending: u64) {
        self.max_pending_input.fetch_max(pending, Ordering::Relaxed);
    }

    pub(crate) fn node_ahead(&self, ahead: u64) {
        self.max_node_ahead.fetch_max(ahead, Ordering::Relaxed);
    }

    pub(crate) fn pinged(&self) {
        self.pings.fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) struct TerminalState {
    installed: Mutex<Option<Arc<Installed>>>,
    keys: Mutex<KeySource>,
    pub(crate) live: Arc<LiveTerminals>,
    pub(crate) denials: audit::DenialLog,
    pub(crate) counters: Counters,
    #[cfg(feature = "test-support")]
    issued: Mutex<Vec<String>>,
}

impl Default for TerminalState {
    fn default() -> Self {
        Self {
            installed: Mutex::new(None),
            keys: Mutex::new(Arc::new(EphemeralKey::generate)),
            live: Arc::default(),
            denials: audit::DenialLog::default(),
            counters: Counters::default(),
            #[cfg(feature = "test-support")]
            issued: Mutex::new(Vec::new()),
        }
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl TerminalState {
    pub(crate) fn install(&self, gate: Arc<dyn TerminalGate>, settings: WebTerminalSettings) {
        *locked(&self.installed) = Some(Arc::new(Installed {
            gate,
            settings,
            tickets: tickets::TicketTable::new(settings.max_tickets),
        }));
    }

    pub(crate) fn installed(&self) -> Option<Arc<Installed>> {
        locked(&self.installed).clone()
    }

    pub(crate) fn new_key(&self) -> Result<EphemeralKey, JumpError> {
        let source = Arc::clone(&*locked(&self.keys));
        source()
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn counters(&self) -> WebTerminalCounters {
        WebTerminalCounters {
            open: self.live.open(),
            max_pending_output: self.counters.max_pending_output.load(Ordering::Relaxed),
            max_pending_input: self.counters.max_pending_input.load(Ordering::Relaxed),
            max_node_ahead: self.counters.max_node_ahead.load(Ordering::Relaxed),
            pings: self.counters.pings.load(Ordering::Relaxed),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn use_keys(&self, source: KeySource) {
        *locked(&self.keys) = source;
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn note_issued(&self, line: &str) {
        locked(&self.issued).push(line.to_owned());
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) fn note_issued(&self, _line: &str) {}

    #[cfg(feature = "test-support")]
    pub(crate) fn issued(&self) -> Vec<String> {
        locked(&self.issued).clone()
    }
}
