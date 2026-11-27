use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_tunnel::StreamKind;
use tokio_util::sync::CancellationToken;

use super::support::{DAY, FakeServiceControl, Lie, approved, fixed, wait_until};
use crate::clock::{Clock, at_unix_secs, unix_secs};
use crate::runtime::certs::{
    SERVICE_CERTIFICATE_BACKOFF, SERVICE_RENEWAL_SPREAD, ServiceCertificates,
};
use crate::testkit::{ManualClock, TestPki, soon};

fn certificates(clock: &Arc<ManualClock>) -> (Arc<FakeServiceControl>, Arc<ServiceCertificates>) {
    let grafana = approved(StreamKind::Tcp, "grafana");
    let control = Arc::new(FakeServiceControl::new(
        Arc::new(TestPki::new()),
        clock.clone(),
        &[grafana],
    ));
    let certificates = Arc::new(ServiceCertificates::new(
        control.clone(),
        clock.clone(),
        fixed(1.0),
        SERVICE_CERTIFICATE_BACKOFF,
    ));
    (control, certificates)
}

#[tokio::test]
async fn parallel_first_connections_share_one_certificate_request() {
    let clock = ManualClock::new(SystemTime::now());
    let (control, certificates) = certificates(&clock);
    let gate = control.hold_certificates();
    let grafana = approved(StreamKind::Tcp, "grafana");
    let waiting: Vec<_> = (0..8)
        .map(|_| {
            let certificates = certificates.clone();
            let grafana = grafana.clone();
            tokio::spawn(async move { certificates.get(&grafana).await })
        })
        .collect();
    wait_until("the first request to reach control", || {
        control.certificate_calls() == 1
    })
    .await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert_eq!(control.certificate_calls(), 1);
    gate.notify_one();
    let mut serials = Vec::new();
    for joined in waiting {
        serials.push(
            soon("a waiting connection", joined)
                .await
                .unwrap()
                .unwrap()
                .serial(),
        );
    }
    assert_eq!(control.certificate_calls(), 1);
    assert!(
        serials.iter().all(|serial| *serial == serials[0]),
        "{serials:?}"
    );
    assert_eq!(
        certificates.get(&grafana).await.unwrap().dns_name(),
        "grafana.tcp.svc.test"
    );
    assert_eq!(control.certificate_calls(), 1);
}

#[tokio::test]
async fn renewal_starts_at_half_life_and_keeps_the_old_certificate_while_control_fails() {
    let start = SystemTime::now();
    let clock = ManualClock::new(start);
    let (control, certificates) = certificates(&clock);
    let grafana = approved(StreamKind::Tcp, "grafana");
    let stop = CancellationToken::new();
    let renewing = tokio::spawn(certificates.clone().run(stop.clone()));

    let first = certificates.get(&grafana).await.unwrap();
    let not_before = unix_secs(start) - 60;
    let half = not_before + (first.not_after() - not_before) / 2;
    let spread = i64::try_from(SERVICE_RENEWAL_SPREAD.as_secs()).unwrap();
    assert_eq!(first.renew_at(), half + spread);
    clock.wait_for_sleeper(at_unix_secs(first.renew_at())).await;

    control.fail_certificates(true);
    clock.set(at_unix_secs(first.renew_at() - 1));
    tokio::task::yield_now().await;
    assert_eq!(control.certificate_calls(), 1);
    clock.set(at_unix_secs(first.renew_at()));
    for (expected_calls, backoff) in [(2, 5), (3, 10), (4, 20)] {
        wait_until("a renewal attempt", || {
            control.certificate_calls() == expected_calls
        })
        .await;
        let retry = clock.now() + Duration::from_secs(backoff);
        clock.wait_for_sleeper(retry).await;
        let kept = certificates.get(&grafana).await.unwrap();
        assert_eq!(kept.serial(), first.serial());
        assert_eq!(control.certificate_calls(), expected_calls);
        clock.set(retry);
    }
    control.fail_certificates(false);
    clock.advance(Duration::from_secs(40));
    wait_until("a successful renewal", || {
        certificates
            .slot_serial(&grafana)
            .is_some_and(|serial| serial != first.serial())
    })
    .await;
    let renewed = certificates.get(&grafana).await.unwrap();
    assert_ne!(renewed.serial(), first.serial());
    assert!(renewed.renew_at() > first.renew_at());
    stop.cancel();
    soon("the renewal task to stop", renewing).await.unwrap();
}

#[tokio::test]
async fn an_expired_certificate_is_not_served_while_control_keeps_failing() {
    let clock = ManualClock::new(SystemTime::now());
    let (control, certificates) = certificates(&clock);
    let grafana = approved(StreamKind::Tcp, "grafana");
    let first = certificates.get(&grafana).await.unwrap();
    control.fail_certificates(true);
    clock.set(at_unix_secs(first.not_after()));
    assert!(certificates.get(&grafana).await.is_err());
    let calls = control.certificate_calls();
    assert!(certificates.get(&grafana).await.is_err());
    assert_eq!(control.certificate_calls(), calls);
    control.fail_certificates(false);
    clock.advance(Duration::from_secs(DAY as u64));
    assert!(certificates.get(&grafana).await.is_ok());
}

#[tokio::test]
async fn a_certificate_that_does_not_fit_the_service_or_the_key_is_refused() {
    let grafana = approved(StreamKind::Tcp, "grafana");
    for lie in [
        Lie::OtherKey,
        Lie::OtherName,
        Lie::SanDiffers,
        Lie::OtherKind,
        Lie::Expired,
        Lie::Garbage,
    ] {
        let clock = ManualClock::new(SystemTime::now());
        let (control, certificates) = certificates(&clock);
        control.lie(Some(lie));
        assert!(certificates.get(&grafana).await.is_err(), "{lie:?}");
        assert_eq!(control.certificate_calls(), 1, "{lie:?}");
        assert_eq!(certificates.slot_serial(&grafana), None, "{lie:?}");
    }
    let clock = ManualClock::new(SystemTime::now());
    let (_control, certificates) = certificates(&clock);
    assert_eq!(
        certificates.get(&grafana).await.unwrap().dns_name(),
        "grafana.tcp.svc.test"
    );
}
