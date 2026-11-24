use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_ca::{DEFAULT_SERVER_VALIDITY, ServerCertParams, SubjectPublicKey};
use jaunt_control::{Clock, Control};
use jaunt_tunnel::RotatingCertificate;
use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

use super::AgentsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) not_before: SystemTime,
    pub(crate) not_after: SystemTime,
}

struct Issued {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    window: Window,
}

pub(crate) struct ServerCertificate {
    control: Control,
    server_name: String,
    clock: Clock,
    slot: Arc<RotatingCertificate>,
    window: Mutex<Window>,
}

impl ServerCertificate {
    pub(crate) fn issue(
        control: Control,
        server_name: String,
        clock: Clock,
    ) -> Result<Self, AgentsError> {
        let issued = issue(&control, &server_name, clock())?;
        let slot = Arc::new(RotatingCertificate::new(issued.chain, issued.key)?);
        Ok(Self {
            control,
            server_name,
            clock,
            slot,
            window: Mutex::new(issued.window),
        })
    }

    pub(crate) fn slot(&self) -> Arc<RotatingCertificate> {
        self.slot.clone()
    }

    pub(crate) fn not_after(&self) -> SystemTime {
        self.window
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .not_after
    }

    fn rotate_if_due(&self) -> Result<bool, AgentsError> {
        let now = (self.clock)();
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        if !renewal_due(*window, now) {
            return Ok(false);
        }
        let issued = issue(&self.control, &self.server_name, now)?;
        self.slot.replace(issued.chain, issued.key)?;
        *window = issued.window;
        rotated(issued.window.not_after);
        Ok(true)
    }
}

pub(crate) fn renewal_due(window: Window, now: SystemTime) -> bool {
    let lifetime = window
        .not_after
        .duration_since(window.not_before)
        .unwrap_or(Duration::ZERO);
    match window.not_after.duration_since(now) {
        Ok(remaining) => remaining < lifetime / 3,
        Err(_) => true,
    }
}

pub(crate) async fn rotate_forever(
    certificate: Arc<ServerCertificate>,
    every: Duration,
    stop: CancellationToken,
) {
    let mut ticker = interval_at(Instant::now() + every, every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => {}
        }
        if let Err(error) = certificate.rotate_if_due() {
            tracing::error!(
                target: "jaunt::agents",
                error = %error,
                "renewing the agents' server certificate failed; the current one stays in use"
            );
        }
    }
}

fn issue(control: &Control, server_name: &str, now: SystemTime) -> Result<Issued, AgentsError> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(AgentsError::Key)?;
    let subject_public_key = SubjectPublicKey::from_spki_der(&key.subject_public_key_info())
        .map_err(AgentsError::Certificate)?;
    let issued = control
        .issue_server_certificate(
            ServerCertParams {
                subject_public_key,
                dns_names: vec![server_name.to_owned()],
                validity: DEFAULT_SERVER_VALIDITY,
            },
            now,
        )
        .map_err(AgentsError::Certificate)?;
    Ok(Issued {
        chain: vec![CertificateDer::from(issued.certificate_der)],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        window: Window {
            not_before: issued.not_before,
            not_after: issued.not_after,
        },
    })
}

fn rotated(not_after: SystemTime) {
    let not_after = not_after
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.cert.rotated",
        not_after
    );
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{Window, renewal_due};

    #[test]
    fn renewal_is_due_once_less_than_a_third_of_the_life_remains() {
        let start = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let window = Window {
            not_before: start,
            not_after: start + Duration::from_secs(30 * 86_400),
        };
        let at = |secs: u64| -> SystemTime { start + Duration::from_secs(secs) };
        for (now, due) in [
            (at(0), false),
            (at(20 * 86_400), false),
            (at(20 * 86_400 + 1), true),
            (at(30 * 86_400), true),
            (at(31 * 86_400), true),
        ] {
            assert_eq!(renewal_due(window, now), due, "{now:?}");
        }
    }
}
