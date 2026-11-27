use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::gate_config::{StoredGateError, ssh_route};
use crate::gate_tls::{GateError, connect};
use crate::profile::ProfileName;
use crate::store::{ProfileStore, StoreError};

const RELAY_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("reading standard input failed: {0}")]
    Input(io::Error),
    #[error("writing to standard output failed: {0}")]
    Output(io::Error),
    #[error("sending to the gate failed: {0}")]
    Send(io::Error),
    #[error("receiving from the gate failed: {0}")]
    Receive(io::Error),
    #[error("the gate closed the connection without ending TLS")]
    CutOff,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error(
        "profile `{profile}` has no TLS route to the gate: run `jaunt login --profile {profile}`"
    )]
    NotSetUp { profile: ProfileName },
    #[error(
        "the stored gate settings of profile `{profile}` cannot be used: {source}; run `jaunt login --profile {profile}`"
    )]
    Settings {
        profile: ProfileName,
        source: StoredGateError,
    },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Gate(#[from] GateError),
    #[error(transparent)]
    Relay(#[from] RelayError),
    #[error("cannot start the connection runtime: {0}")]
    Runtime(io::Error),
}

pub fn proxy_ssh(store: &ProfileStore, profile: &ProfileName, now: i64) -> Result<(), ProxyError> {
    let stored = store
        .read_gate_services()?
        .ok_or_else(|| ProxyError::NotSetUp {
            profile: profile.clone(),
        })?;
    let route = ssh_route(&stored, now).map_err(|source| ProxyError::Settings {
        profile: profile.clone(),
        source,
    })?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(ProxyError::Runtime)?;
    let outcome = runtime.block_on(async {
        let stream = connect(&route).await?;
        relay(tokio::io::stdin(), tokio::io::stdout(), stream).await?;
        Ok(())
    });
    runtime.shutdown_background();
    outcome
}

pub async fn relay<I, O, S>(mut input: I, mut output: O, stream: S) -> Result<(), RelayError>
where
    I: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut from_gate, mut to_gate) = tokio::io::split(stream);
    let sending = uplink(&mut input, &mut to_gate);
    let receiving = downlink(&mut from_gate, &mut output);
    tokio::pin!(sending, receiving);
    let mut still_sending = true;
    loop {
        tokio::select! {
            biased;
            received = &mut receiving => return received,
            sent = &mut sending, if still_sending => {
                sent?;
                still_sending = false;
            }
        }
    }
}

async fn uplink<I, W>(input: &mut I, to_gate: &mut W) -> Result<(), RelayError>
where
    I: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
    loop {
        let count = input.read(&mut buffer).await.map_err(RelayError::Input)?;
        if count == 0 {
            break;
        }
        to_gate
            .write_all(&buffer[..count])
            .await
            .map_err(RelayError::Send)?;
        to_gate.flush().await.map_err(RelayError::Send)?;
    }
    to_gate.shutdown().await.map_err(RelayError::Send)
}

async fn downlink<R, O>(from_gate: &mut R, output: &mut O) -> Result<(), RelayError>
where
    R: AsyncRead + Unpin,
    O: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
    loop {
        let count = match from_gate.read(&mut buffer).await {
            Ok(0) => break,
            Ok(count) => count,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(RelayError::CutOff);
            }
            Err(err) => return Err(RelayError::Receive(err)),
        };
        output
            .write_all(&buffer[..count])
            .await
            .map_err(RelayError::Output)?;
        output.flush().await.map_err(RelayError::Output)?;
    }
    output.flush().await.map_err(RelayError::Output)
}
