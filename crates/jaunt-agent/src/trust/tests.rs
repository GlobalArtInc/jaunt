use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_ssh::{AgentLimits, InnerCa, InnerTarget, UserCaKeys};
use jaunt_tunnel::{BackoffPolicy, ClientEvent, StreamHandler};
use serde_json::json;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{
    Reconnections, Signal, TRUST_TIMING, TrustEnd, TrustLoader, TrustTiming, clock_skew, spread,
};
use crate::ssh::{ControlAuthority, SshService};
use crate::testkit::{
    ApiStep, FakeGate, LogCapture, ManualClock, TRUST_PATH, eventually, gate_and_api, soon,
    trust_reply, user_ca_line,
};

const HOUR: Duration = Duration::from_secs(3600);

const FAST: TrustTiming = TrustTiming {
    backoff: BackoffPolicy {
        initial: Duration::from_millis(5),
        max: Duration::from_millis(20),
        reset_after: Duration::from_secs(60),
    },
    refresh_min: HOUR,
    refresh_max: HOUR,
    wake_jitter: Duration::from_millis(1),
};

struct Loading {
    gate: FakeGate,
    service: Arc<SshService>,
    events: broadcast::Sender<ClientEvent>,
    shutdown: CancellationToken,
    task: JoinHandle<TrustEnd>,
}

struct Options {
    timing: TrustTiming,
    sample: f64,
    capacity: usize,
}

const DEFAULTS: Options = Options {
    timing: FAST,
    sample: 1.0,
    capacity: 8,
};

async fn loading(clock: Arc<ManualClock>, prepare: impl FnOnce(&FakeGate)) -> Loading {
    loading_with(DEFAULTS, clock, prepare).await
}

async fn loading_with(
    options: Options,
    clock: Arc<ManualClock>,
    prepare: impl FnOnce(&FakeGate),
) -> Loading {
    let (gate, api) = gate_and_api().await;
    prepare(&gate);
    let service = Arc::new(SshService::new(
        Arc::new(InnerCa::generate().unwrap()),
        InnerTarget {
            sshd_addr: "127.0.0.1:22".parse().unwrap(),
            sshd_host_key: "/nonexistent/ssh_host_ed25519_key.pub".into(),
        },
        Arc::new(ControlAuthority::new(api.clone())),
        AgentLimits::default(),
    ));
    let shutdown = CancellationToken::new();
    let (events, receiver) = broadcast::channel(options.capacity);
    let sample = options.sample;
    let loader = TrustLoader {
        api,
        ssh: service.clone(),
        clock,
        timing: options.timing,
        events: Some(receiver),
        sample: Arc::new(move || sample),
    };
    let task = tokio::spawn(loader.run(shutdown.clone()));
    Loading {
        gate,
        service,
        events,
        shutdown,
        task,
    }
}

fn ecdsa_line() -> String {
    russh::keys::PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        },
    )
    .unwrap()
    .public_key()
    .to_openssh()
    .unwrap()
}

#[test]
fn delays_spread_between_their_bounds() {
    let (min, max) = (Duration::from_secs(600), Duration::from_secs(900));
    for (sample, expected) in [
        (0.0, 600),
        (0.5, 750),
        (1.0, 900),
        (-3.0, 600),
        (7.0, 900),
        (f64::NAN, 600),
    ] {
        assert_eq!(spread(min, max, sample), Duration::from_secs(expected));
    }
    assert_eq!(spread(max, min, 1.0), max);
    assert_eq!(TRUST_TIMING.refresh_min, Duration::from_secs(600));
    assert_eq!(TRUST_TIMING.refresh_max, Duration::from_secs(900));
    assert_eq!(TRUST_TIMING.wake_jitter, Duration::from_secs(5));
}

#[tokio::test]
async fn a_tunnel_reconnection_refetches_and_earlier_reconnections_are_covered_by_the_load() {
    let loading = loading(ManualClock::new(SystemTime::now()), |_| {}).await;
    loading.events.send(ClientEvent::Connected).unwrap();
    eventually("the trust set to load", || loading.trust().is_some()).await;
    let after_load = loading.gate.requests(TRUST_PATH).len();
    loading
        .events
        .send(ClientEvent::Disconnected { lasted: HOUR })
        .unwrap();
    loading.events.send(ClientEvent::Connected).unwrap();
    eventually("the reconnection to refetch", || {
        loading.gate.requests(TRUST_PATH).len() == after_load + 1
    })
    .await;
    assert_eq!(after_load, 1);
    loading.stop().await;
}

#[tokio::test]
async fn the_set_is_refreshed_periodically_without_any_announcement() {
    let timing = TrustTiming {
        refresh_min: Duration::from_millis(10),
        refresh_max: Duration::from_millis(20),
        ..FAST
    };
    let options = Options { timing, ..DEFAULTS };
    let loading = loading_with(options, ManualClock::new(SystemTime::now()), |_| {}).await;
    eventually("three periodic fetches", || {
        loading.gate.requests(TRUST_PATH).len() >= 3
    })
    .await;
    loading.stop().await;
}

#[test]
fn only_a_reconnection_after_the_first_connection_or_a_lag_asks_for_a_reload() {
    let mut reconnections = Reconnections::default();
    let disconnected = Signal::Event(ClientEvent::Disconnected { lasted: HOUR });
    for (signal, reload) in [
        (disconnected, false),
        (Signal::Event(ClientEvent::Connected), false),
        (disconnected, false),
        (Signal::Event(ClientEvent::Connected), true),
        (Signal::Event(ClientEvent::Connected), true),
    ] {
        assert_eq!(reconnections.wants_reload(signal), reload, "{signal:?}");
    }
    let mut lagged = Reconnections::default();
    assert!(lagged.wants_reload(Signal::Lagged));
    assert!(lagged.wants_reload(Signal::Event(ClientEvent::Connected)));
}

#[tokio::test]
async fn the_first_connection_after_the_initial_load_does_not_refetch() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let loading = loading(ManualClock::new(SystemTime::now()), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    loading.events.send(ClientEvent::Connected).unwrap();
    loading
        .events
        .send(ClientEvent::Disconnected { lasted: HOUR })
        .unwrap();
    loading.events.send(ClientEvent::Connected).unwrap();
    eventually("the reconnection to refetch", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    loading.service.trust_update();
    eventually("the announcement to refetch", || {
        logs.text().contains("\"wake\":\"announced\"")
            && loading.gate.requests(TRUST_PATH).len() == 3
    })
    .await;
    assert_eq!(logs.text().matches("\"wake\":\"reconnected\"").count(), 1);
    loading.stop().await;
}

#[tokio::test]
async fn a_lagging_event_channel_asks_for_a_reload() {
    let options = Options {
        capacity: 1,
        ..DEFAULTS
    };
    let loading = loading_with(options, ManualClock::new(SystemTime::now()), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    for _ in 0..3 {
        loading
            .events
            .send(ClientEvent::Disconnected { lasted: HOUR })
            .unwrap();
    }
    eventually("the lag to refetch", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    loading.stop().await;
}

#[tokio::test]
async fn the_delay_after_an_announcement_uses_the_injected_sample() {
    let immediate = Options {
        timing: TrustTiming {
            wake_jitter: HOUR,
            ..FAST
        },
        sample: 0.0,
        ..DEFAULTS
    };
    let loading = loading_with(immediate, ManualClock::new(SystemTime::now()), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    loading.service.trust_update();
    eventually("a sample of zero to refetch at once", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    loading.stop().await;

    let delayed = Options {
        timing: TrustTiming {
            wake_jitter: Duration::from_millis(300),
            ..FAST
        },
        sample: 1.0,
        ..DEFAULTS
    };
    let loading = loading_with(delayed, ManualClock::new(SystemTime::now()), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    let announced = std::time::Instant::now();
    loading.service.trust_update();
    eventually("a sample of one to refetch after the full delay", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    assert!(announced.elapsed() >= Duration::from_millis(300));
    loading.stop().await;
}

impl Loading {
    fn trust(&self) -> Option<Arc<UserCaKeys>> {
        self.service.trust()
    }

    async fn stop(self) -> TrustEnd {
        self.shutdown.cancel();
        let end = soon("the loader to stop", self.task).await.unwrap();
        self.gate.stop().await;
        end
    }
}

fn keys(lines: &[String]) -> UserCaKeys {
    UserCaKeys::from_openssh_lines(lines).unwrap()
}

#[test]
fn clock_skew_is_the_distance_either_way() {
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_000_000);
    for (local, server, skew) in [
        (base, base, 0),
        (base + Duration::from_secs(61), base, 61),
        (base, base + Duration::from_secs(90), 90),
    ] {
        assert_eq!(clock_skew(local, server), Duration::from_secs(skew));
    }
}

#[tokio::test]
async fn the_first_trust_set_is_loaded_and_a_large_clock_skew_is_reported_once() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let now = SystemTime::now();
    let lines = vec![user_ca_line(), user_ca_line()];
    let standing = lines.clone();
    let loading = loading(ManualClock::new(now), |gate| {
        gate.set_standing(TRUST_PATH, trust_reply(&standing));
        gate.set_server_time(Some(now - Duration::from_secs(120)));
    })
    .await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    assert_eq!(*loading.trust().unwrap(), keys(&lines));
    eventually("the skew to be reported", || {
        logs.text().contains("agent.clock_skew")
    })
    .await;
    assert!(logs.text().contains("\"skew_secs\":120"));

    loading.service.trust_update();
    eventually("the update to be fetched", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    assert_eq!(logs.text().matches("agent.clock_skew").count(), 1);
    assert_eq!(loading.stop().await, TrustEnd::Shutdown);
}

#[tokio::test]
async fn a_small_skew_is_not_reported() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let now = SystemTime::now();
    let loading = loading(ManualClock::new(now), |gate| {
        gate.set_server_time(Some(now + Duration::from_secs(30)));
    })
    .await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    loading.stop().await;
    assert!(!logs.text().contains("agent.clock_skew"));
}

#[tokio::test]
async fn failed_and_invalid_sets_are_retried_and_never_installed() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let lines = vec![user_ca_line()];
    let standing = lines.clone();
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.script(
            TRUST_PATH,
            vec![
                ApiStep::Json(503, json!({"error": "unavailable"})),
                ApiStep::Json(200, json!({"user_ca_keys": []})),
                ApiStep::Json(200, json!({"user_ca_keys": ["ssh-ed25519 not-base64"]})),
                ApiStep::Json(200, json!({"user_ca_keys": [standing[0], standing[0]]})),
                ApiStep::Json(200, json!({"user_ca_keys": [standing[0], ecdsa_line()]})),
            ],
        );
        gate.set_standing(TRUST_PATH, trust_reply(&standing));
    })
    .await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    assert_eq!(*loading.trust().unwrap(), keys(&lines));
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 6);
    assert_eq!(
        logs.text()
            .matches("loading the user CA trust set failed")
            .count(),
        5
    );
    loading.stop().await;
}

#[tokio::test]
async fn an_update_replaces_the_set_and_an_invalid_update_keeps_the_previous_one() {
    let first = vec![user_ca_line()];
    let standing = first.clone();
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(TRUST_PATH, trust_reply(&standing));
    })
    .await;
    eventually("the first set to load", || loading.trust().is_some()).await;

    let second = vec![user_ca_line(), first[0].clone()];
    loading.gate.set_standing(TRUST_PATH, trust_reply(&second));
    loading.service.trust_update();
    eventually("the second set to replace the first", || {
        loading
            .trust()
            .is_some_and(|current| *current == keys(&second))
    })
    .await;

    loading
        .gate
        .set_standing(TRUST_PATH, ApiStep::Json(200, json!({"user_ca_keys": []})));
    let before = loading.gate.requests(TRUST_PATH).len();
    loading.service.trust_update();
    eventually("the invalid set to be fetched and retried", || {
        loading.gate.requests(TRUST_PATH).len() >= before + 2
    })
    .await;
    assert_eq!(*loading.trust().unwrap(), keys(&second));
    loading.stop().await;
}

#[tokio::test]
async fn a_removed_node_stops_loading() {
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(
            TRUST_PATH,
            ApiStep::Json(403, json!({"error": "node_removed"})),
        );
    })
    .await;
    eventually("the loader to stop by itself", || {
        loading.task.is_finished()
    })
    .await;
    assert!(loading.trust().is_none());
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 1);
    assert_eq!(loading.stop().await, TrustEnd::NodeRemoved);
}
