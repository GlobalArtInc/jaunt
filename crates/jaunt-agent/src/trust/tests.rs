use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_proto::{AGENT_TRUST_V3_PATH, TrustRole};
use jaunt_ssh::{AgentLimits, InnerCa, InnerTarget, NoObserver, UserCaKeys};
use jaunt_tunnel::{BackoffPolicy, ClientEvent, StreamHandler};
use serde_json::json;
use ssh_key::public::KeyData;
use tokio::sync::{Notify, broadcast, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{
    Reconnections, Signal, TRUST_TIMING, TrustEnd, TrustLoader, TrustTiming, clock_skew, spread,
};
use crate::runtime::tests::support::{UserCa, UserSpec};
use crate::runtime::x509::{UserX509Trust, verify_user};
use crate::ssh::{ControlAuthority, SshService};
use crate::testkit::{
    ApiStep, FakeGate, LogCapture, ManualClock, TRUST_PATH, TRUST_V2_PATH, eventually,
    gate_and_api, soon, trust_reply, trust_v2_reply, unix_now, user_ca_line,
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
    refusal_interval: MINUTE,
};

const MINUTE: Duration = Duration::from_secs(60);

struct Loading {
    gate: FakeGate,
    service: Arc<SshService>,
    events: broadcast::Sender<ClientEvent>,
    shutdown: CancellationToken,
    task: JoinHandle<TrustEnd>,
    host_ca: watch::Receiver<Option<KeyData>>,
    user_x509: Arc<UserX509Trust>,
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
        Arc::new(NoObserver),
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
        host_ca: watch::Sender::new(None),
        user_x509: Arc::new(UserX509Trust::default()),
    };
    let host_ca = loader.host_ca.subscribe();
    let user_x509 = loader.user_x509.clone();
    let task = tokio::spawn(loader.run(shutdown.clone()));
    Loading {
        gate,
        service,
        events,
        shutdown,
        task,
        host_ca,
        user_x509,
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
    assert_eq!(TRUST_TIMING.refusal_interval, MINUTE);
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

#[tokio::test]
async fn a_flood_of_refusals_reads_the_trust_set_at_most_once_a_minute() {
    let t0 = SystemTime::now();
    let clock = ManualClock::new(t0);
    let loading = loading(clock.clone(), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    let refusals = loading.service.untrusted_refusals();
    let reads = || loading.gate.requests(TRUST_PATH).len();
    for _ in 0..1000 {
        refusals.record();
    }
    eventually("one read for the burst", || reads() == 2).await;

    for _ in 0..1000 {
        refusals.record();
    }
    clock.wait_for_sleeper(t0 + MINUTE).await;
    clock.advance(Duration::from_secs(30));
    for _ in 0..1000 {
        refusals.record();
    }
    clock.wait_for_sleeper(t0 + MINUTE).await;
    assert_eq!(reads(), 2);

    clock.set(t0 + MINUTE);
    eventually("the second read a minute later", || reads() == 3).await;
    for _ in 0..1000 {
        refusals.record();
    }
    clock.set(t0 + Duration::from_secs(90));
    clock.wait_for_sleeper(t0 + 2 * MINUTE).await;
    assert_eq!(reads(), 3);
    loading.stop().await;
}

#[tokio::test]
async fn a_failed_read_after_a_refusal_is_retried_a_minute_later() {
    let t0 = SystemTime::now();
    let clock = ManualClock::new(t0);
    let loading = loading(clock.clone(), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    let lines = vec![user_ca_line()];
    loading.gate.script(
        TRUST_PATH,
        vec![ApiStep::Json(503, json!({"error": "unavailable"}))],
    );
    loading.gate.set_standing(TRUST_PATH, trust_reply(&lines));
    loading.service.untrusted_refusals().record();
    clock.wait_for_sleeper(t0 + MINUTE).await;
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 2);
    assert_ne!(*loading.trust().unwrap(), keys(&lines));

    clock.set(t0 + MINUTE);
    eventually("the retried read to install the set", || {
        loading
            .trust()
            .is_some_and(|current| *current == keys(&lines))
    })
    .await;
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 3);
    loading.stop().await;
}

#[tokio::test]
async fn an_announcement_during_a_stalled_refusal_read_is_applied_after_it() {
    let clock = ManualClock::new(SystemTime::now());
    let loading = loading(clock.clone(), |_| {}).await;
    eventually("the trust set to load", || loading.trust().is_some()).await;
    let (stalled, newest) = (vec![user_ca_line()], vec![user_ca_line()]);
    let release = Arc::new(Notify::new());
    loading.gate.script(
        TRUST_PATH,
        vec![ApiStep::Held(
            release.clone(),
            Box::new(trust_reply(&stalled)),
        )],
    );
    loading.gate.set_standing(TRUST_PATH, trust_reply(&newest));
    let refusals = loading.service.untrusted_refusals();
    refusals.record();
    eventually("the refusal read to stall", || {
        loading.gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    loading.service.trust_update();
    let started = std::time::Instant::now();
    for _ in 0..10_000 {
        refusals.record();
    }
    assert!(started.elapsed() < Duration::from_secs(1));
    tokio::task::yield_now().await;
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 2);

    release.notify_one();
    eventually("the announced set to replace the stalled one", || {
        loading
            .trust()
            .is_some_and(|current| *current == keys(&newest))
    })
    .await;
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 3);
    assert!(clock.sleepers().is_empty());
    loading.stop().await;
}

fn loaded(logs: &LogCapture) -> usize {
    logs.text().matches("loaded the user CA trust set").count()
}

#[tokio::test]
async fn a_served_refusal_does_not_keep_reading_once_a_minute() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = SystemTime::now();
    let clock = ManualClock::new(t0);
    let loading = loading(clock.clone(), |_| {}).await;
    eventually("the trust set to load", || loaded(&logs) == 1).await;
    loading.service.untrusted_refusals().record();
    eventually("the refusal read", || loaded(&logs) == 2).await;
    assert!(clock.sleepers().is_empty());
    for minute in 1..=5 {
        clock.set(t0 + minute * MINUTE);
        tokio::task::yield_now().await;
    }
    assert!(clock.sleepers().is_empty());
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 2);
    loading.stop().await;
}

#[tokio::test]
async fn a_clock_set_back_does_not_freeze_the_read_after_a_refusal() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = SystemTime::now();
    let clock = ManualClock::new(t0);
    let loading = loading(clock.clone(), |_| {}).await;
    eventually("the trust set to load", || loaded(&logs) == 1).await;
    let refusals = loading.service.untrusted_refusals();
    refusals.record();
    eventually("the refusal read", || loaded(&logs) == 2).await;

    let back = t0 - HOUR;
    clock.set(back);
    refusals.record();
    clock.wait_for_sleeper(back + MINUTE).await;
    assert_eq!(loading.gate.requests(TRUST_PATH).len(), 2);
    clock.set(back + MINUTE);
    eventually("the read a minute after the clock was set back", || {
        loaded(&logs) == 3
    })
    .await;
    loading.stop().await;
}

#[tokio::test]
async fn an_unreadable_active_host_key_still_installs_the_user_keys_and_publishes_nothing() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let first = vec![user_ca_line()];
    let reply = trust_v2_reply(&first, "ssh-ed25519 not-base64");
    let mut loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(TRUST_V2_PATH, reply);
    })
    .await;
    eventually("the first set to load", || {
        loading
            .trust()
            .is_some_and(|current| *current == keys(&first))
    })
    .await;
    assert!(
        logs.text()
            .contains("active host CA key that cannot be read")
    );
    assert_eq!(*loading.host_ca.borrow_and_update(), None);

    let (second, host_ca) = (vec![user_ca_line()], user_ca_line());
    loading
        .gate
        .set_standing(TRUST_V2_PATH, trust_v2_reply(&second, &host_ca));
    loading.service.trust_update();
    soon(
        "the readable key to be published",
        loading.host_ca.changed(),
    )
    .await
    .unwrap();
    let expected = ssh_key::PublicKey::from_openssh(&host_ca)
        .unwrap()
        .key_data()
        .clone();
    assert_eq!(*loading.host_ca.borrow(), Some(expected));
    assert_eq!(*loading.trust().unwrap(), keys(&second));
    assert!(loading.gate.requests(TRUST_PATH).is_empty());
    loading.stop().await;
}

fn v3_reply(roots: &[jaunt_proto::TrustedX509Root]) -> ApiStep {
    ApiStep::Json(
        200,
        json!({
            "trust_id": "t3",
            "user_ca_keys": [user_ca_line()],
            "host_ca_active": user_ca_line(),
            "user_x509_roots": roots,
        }),
    )
}

fn accepts(loading: &Loading, ca: &UserCa, now: i64) -> bool {
    let user = ca.issue(&UserSpec::valid(now));
    verify_user(&user.der, &loading.user_x509.snapshot(), now).is_ok()
}

#[tokio::test]
async fn the_third_version_installs_the_user_roots_and_a_refresh_adds_a_rotated_next_root() {
    let now = unix_now();
    let (active, next) = (UserCa::new(now), UserCa::new(now));
    let first = v3_reply(&[active.root(TrustRole::Active)]);
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(AGENT_TRUST_V3_PATH, first);
    })
    .await;
    eventually("the active root to load", || {
        accepts(&loading, &active, now)
    })
    .await;
    assert!(!accepts(&loading, &next, now));
    assert!(loading.trust().is_some());
    assert!(loading.gate.requests(TRUST_V2_PATH).is_empty());

    loading.gate.set_standing(
        AGENT_TRUST_V3_PATH,
        v3_reply(&[active.root(TrustRole::Active), next.root(TrustRole::Next)]),
    );
    loading.service.trust_update();
    eventually("the rotated next root to load", || {
        accepts(&loading, &next, now)
    })
    .await;
    assert!(accepts(&loading, &active, now));

    let mut broken = next.root(TrustRole::Next);
    broken.fingerprint = active.fingerprint();
    loading.gate.set_standing(
        AGENT_TRUST_V3_PATH,
        v3_reply(&[active.root(TrustRole::Active), broken]),
    );
    let before = loading.gate.requests(AGENT_TRUST_V3_PATH).len();
    loading.service.trust_update();
    eventually("the broken set to be read", || {
        loading.gate.requests(AGENT_TRUST_V3_PATH).len() > before
    })
    .await;
    assert!(accepts(&loading, &next, now));
    loading.stop().await;
}

#[tokio::test]
async fn an_empty_or_missing_third_version_leaves_every_user_certificate_refused() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let empty = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(AGENT_TRUST_V3_PATH, v3_reply(&[]));
    })
    .await;
    eventually("the trust set to load", || empty.trust().is_some()).await;
    assert!(empty.user_x509.snapshot().is_empty());
    assert!(!accepts(&empty, &ca, now));
    empty.stop().await;

    let missing = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.set_standing(
            TRUST_V2_PATH,
            trust_v2_reply(&[user_ca_line()], &user_ca_line()),
        );
    })
    .await;
    eventually("the second version to load", || missing.trust().is_some()).await;
    assert_eq!(missing.gate.requests(AGENT_TRUST_V3_PATH).len(), 1);
    assert!(missing.user_x509.snapshot().is_empty());
    assert!(!accepts(&missing, &ca, now));
    missing.stop().await;
}

#[tokio::test]
async fn a_reconnection_asks_for_the_third_version_again() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let v2 = trust_v2_reply(&[user_ca_line()], &user_ca_line());
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.script(
            AGENT_TRUST_V3_PATH,
            vec![ApiStep::Json(404, json!({"error": "not_found"}))],
        );
        gate.set_standing(TRUST_V2_PATH, v2);
    })
    .await;
    eventually("the second version to load", || loading.trust().is_some()).await;
    assert!(!accepts(&loading, &ca, now));
    loading
        .gate
        .set_standing(AGENT_TRUST_V3_PATH, v3_reply(&[ca.root(TrustRole::Active)]));
    loading.service.trust_update();
    eventually("the announced reload", || {
        loading.gate.requests(TRUST_V2_PATH).len() >= 2
    })
    .await;
    assert_eq!(loading.gate.requests(AGENT_TRUST_V3_PATH).len(), 1);
    assert!(!accepts(&loading, &ca, now));

    loading.events.send(ClientEvent::Connected).unwrap();
    loading.events.send(ClientEvent::Connected).unwrap();
    eventually("the third version after the reconnection", || {
        accepts(&loading, &ca, now)
    })
    .await;
    assert_eq!(loading.gate.requests(AGENT_TRUST_V3_PATH).len(), 2);
    loading.stop().await;
}

#[tokio::test]
async fn a_control_plane_that_stops_serving_the_third_version_drops_the_user_roots() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let loading = loading(ManualClock::new(SystemTime::now()), |gate| {
        gate.script(
            AGENT_TRUST_V3_PATH,
            vec![
                v3_reply(&[ca.root(TrustRole::Active)]),
                ApiStep::Json(404, json!({"error": "not_found"})),
            ],
        );
        gate.set_standing(
            TRUST_V2_PATH,
            trust_v2_reply(&[user_ca_line()], &user_ca_line()),
        );
    })
    .await;
    eventually("the roots to load", || accepts(&loading, &ca, now)).await;
    loading.service.trust_update();
    eventually("the downgrade to be read", || {
        !loading.gate.requests(TRUST_V2_PATH).is_empty()
    })
    .await;
    eventually("the roots to be dropped", || !accepts(&loading, &ca, now)).await;
    assert!(loading.user_x509.snapshot().is_empty());
    loading.stop().await;
}
