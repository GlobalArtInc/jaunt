use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use jaunt_fake_idp::{Settings, State, load_users, router};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(
    about = "A fake OpenID Connect provider for end-to-end tests; never run it in production"
)]
struct Args {
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: SocketAddr,
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    client_id: String,
    #[arg(long, value_name = "PATH")]
    client_secret_file: PathBuf,
    #[arg(long = "redirect-uri", required = true)]
    redirect_uris: Vec<String>,
    #[arg(long, value_name = "PATH")]
    users: PathBuf,
    #[arg(long, default_value_t = 3600)]
    session_ttl_secs: u64,
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Users(#[from] jaunt_fake_idp::SettingsError),
    #[error("{path}: {source}")]
    Secret {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("the client secret file is empty")]
    EmptySecret,
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot install the signal handlers: {0}")]
    Signals(#[source] std::io::Error),
    #[error("serving failed: {0}")]
    Serve(#[source] std::io::Error),
}

async fn run(args: Args) -> Result<(), RunError> {
    let secret =
        std::fs::read_to_string(&args.client_secret_file).map_err(|source| RunError::Secret {
            path: args.client_secret_file.display().to_string(),
            source,
        })?;
    let client_secret = secret.trim_end_matches(['\r', '\n']).to_owned();
    if client_secret.is_empty() {
        return Err(RunError::EmptySecret);
    }
    let users = load_users(&args.users)?;
    let state = Arc::new(State::new(Settings {
        issuer: args.issuer.trim_end_matches('/').to_owned(),
        client_id: args.client_id,
        client_secret,
        redirect_uris: args.redirect_uris,
        users,
        session_ttl: Duration::from_secs(args.session_ttl_secs),
    }));
    let listener = TcpListener::bind(args.listen)
        .await
        .map_err(|source| RunError::Listen {
            addr: args.listen,
            source,
        })?;
    let mut terminate = signal(SignalKind::terminate()).map_err(RunError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(RunError::Signals)?;
    println!("fake idp listening on {}", args.listen);
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        })
        .await
        .map_err(RunError::Serve)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}
