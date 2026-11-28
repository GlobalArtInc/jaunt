use std::sync::Arc;

use crate::local_listen::bind_loopback_pair;
use crate::local_proxy::{LocalListener, RunError, StopSignals, Target, proxy_runtime, serve};
use crate::service_dial::{DialKind, ServiceDialer, ServiceName};

pub fn proxy_tcp(
    dialer: Arc<ServiceDialer>,
    name: &ServiceName,
    port: u16,
) -> Result<(), RunError> {
    let target = Arc::new(Target::new(dialer, DialKind::Tcp, name.clone()));
    let runtime = proxy_runtime()?;
    let outcome = runtime.block_on(async {
        let mut signals = StopSignals::install().map_err(RunError::Signals)?;
        let listener = LocalListener::tcp(bind_loopback_pair(port)?)?;
        for address in listener.addresses() {
            println!("Listening on {address}");
        }
        eprintln!(
            "jaunt: warning: every user of this computer can connect to these addresses and reach tcp service `{name}` as you"
        );
        serve(listener, target, signals.stopped()).await;
        Ok(())
    });
    runtime.shutdown_background();
    outcome
}
