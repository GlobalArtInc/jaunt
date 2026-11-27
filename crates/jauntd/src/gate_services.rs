use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_ca::ClientSlot;
use jaunt_control::{Clock, Control};
use jaunt_gate::{
    ClassHandlers, ServiceGate, ServiceGateConfig, ServiceGateError, ServiceGateParts, SshGate,
    UserX509Roots, UserX509Source,
};
use jaunt_proto::{ControlPlane, GateTlsIssuer};
use jaunt_tunnel::AgentRegistry;
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

struct Seen {
    slot: Arc<ClientSlot>,
    roots: Option<Arc<UserX509Roots>>,
}

pub struct ControlUserX509 {
    control: Control,
    seen: Mutex<Option<Seen>>,
}

impl ControlUserX509 {
    pub fn new(control: Control) -> Self {
        Self {
            control,
            seen: Mutex::new(None),
        }
    }

    fn seen(&self) -> MutexGuard<'_, Option<Seen>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl UserX509Source for ControlUserX509 {
    fn current(&self) -> Option<Arc<UserX509Roots>> {
        let slot = self.control.user_x509()?;
        let mut seen = self.seen();
        if let Some(known) = seen.as_ref()
            && Arc::ptr_eq(&known.slot, &slot)
        {
            return known.roots.clone();
        }
        let roots = match UserX509Roots::from_der(
            slot.roots.iter().map(|root| root.certificate_der.clone()),
        ) {
            Ok(roots) => Some(Arc::new(roots)),
            Err(error) => {
                tracing::error!(
                    target: "jaunt::gate",
                    error = %error,
                    "the user-x509 roots cannot verify client certificates; database and tcp connections are refused"
                );
                None
            }
        };
        *seen = Some(Seen {
            slot,
            roots: roots.clone(),
        });
        roots
    }
}

pub struct GateServicesParts {
    pub domain: String,
    pub control: Control,
    pub registry: AgentRegistry,
    pub ssh: Option<Arc<SshGate>>,
    pub clock: Clock,
}

pub struct GateServices {
    gate: Arc<ServiceGate>,
    renewal: JoinHandle<()>,
    stop: CancellationToken,
    _stop_on_drop: DropGuard,
}

impl GateServices {
    pub async fn start(parts: GateServicesParts) -> Result<Self, ServiceGateError> {
        let GateServicesParts {
            domain,
            control,
            registry,
            ssh,
            clock,
        } = parts;
        let issuer: Arc<dyn GateTlsIssuer> = Arc::new(control.clone());
        let plane: Arc<dyn ControlPlane> = Arc::new(control.clone());
        let gate = Arc::new(
            ServiceGate::new(ServiceGateParts {
                config: ServiceGateConfig::new(domain),
                issuer,
                user_x509: Arc::new(ControlUserX509::new(control)),
                control: plane,
                registry,
                ssh,
                clock,
            })
            .await?,
        );
        let stop = CancellationToken::new();
        let renewing = Arc::clone(&gate);
        let token = stop.clone();
        let renewal = tokio::spawn(async move { renewing.renew_forever(token).await });
        Ok(Self {
            gate,
            renewal,
            _stop_on_drop: stop.clone().drop_guard(),
            stop,
        })
    }

    pub fn gate(&self) -> &Arc<ServiceGate> {
        &self.gate
    }

    pub fn handlers(&self) -> ClassHandlers {
        self.gate.handlers()
    }

    pub async fn shutdown(self, grace: Duration) {
        let Self {
            mut renewal, stop, ..
        } = self;
        stop.cancel();
        match tokio::time::timeout(grace, &mut renewal).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                tracing::error!(target: "jaunt::gate", "the gate certificate renewal task panicked");
            }
            Err(_) => {
                renewal.abort();
                tracing::warn!(
                    target: "jaunt::gate",
                    "the gate certificate renewal did not stop within the shutdown grace and was aborted"
                );
            }
        }
    }
}
