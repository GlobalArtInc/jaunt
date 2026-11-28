pub(crate) mod args;
mod client;
#[cfg(test)]
mod tests;
pub(crate) mod token;

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use jaunt_proto::{EnrollRequest, EnrollmentApproved, PollRequest, PollResponse};
use zeroize::Zeroize;

pub use args::EnrollArgs;

use crate::AGENT_VERSION;
use crate::clock::{Clock, SystemClock, format_utc, unix_secs};
use crate::endpoint::AgentEndpoint;
use crate::fsio::{effective_uid, running_as_root};
use crate::keys::{HostKey, KeyError, TlsKey};
use crate::pin::CaPin;
use crate::state::{EnrollmentFiles, EnrollmentRecord, StateDir, StateError, StoreFailure};
use crate::verify::{self, Checked, Expected, VerifyError};
use args::{ServerUrl, parse_hostname};
use client::{CallError, EnrollClient};
use token::{JoinToken, TokenFileError, read_token_file};

const MIN_POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
const RATE_LIMITED_WAIT: Duration = Duration::from_secs(10);
const MAX_CODE_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error(
        "{dir} already holds an enrollment; run again with --replace to replace it (the old files are kept in a previous-* directory)"
    )]
    AlreadyEnrolled { dir: String },
    #[error("cannot determine the system hostname ({reason}); pass --hostname")]
    Hostname { reason: &'static str },
    #[error("cannot use the join token file: {0}")]
    TokenFile(#[source] TokenFileError),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot prepare the state directory: {0}")]
    Prepare(#[source] StateError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error("the enrollment request failed: {0}")]
    Request(#[source] CallError),
    #[error(
        "the server refused the request: the name is already used by an active node; run again with --replace to replace that node"
    )]
    NameTaken,
    #[error("the server is rate limiting enrollment requests from this address; try again later")]
    RateLimited,
    #[error(
        "the server refused the join token: it is unknown, expired, used up or revoked, or it does not allow this name, these labels or --replace"
    )]
    TokenRefused,
    #[error("the server sent an enrollment code that cannot be shown safely")]
    BadCode,
    #[error("polling the enrollment failed: {0}")]
    Poll(#[source] CallError),
    #[error("an administrator rejected the enrollment")]
    Rejected,
    #[error(
        "the enrollment expired on the server before an administrator approved it; run enroll again"
    )]
    Expired,
    #[error("no decision arrived within {secs} seconds; run enroll again")]
    TimedOut { secs: u64 },
    #[error(
        "the server delivered the certificates for this enrollment but this agent did not receive them (a lost response); run `jaunt-agent enroll` again with --replace"
    )]
    AlreadyDelivered,
    #[error("the server no longer knows this enrollment; run enroll again")]
    NotFound,
    #[error("the internal CA root sent by the server does not match --ca-pin; nothing was stored")]
    PinMismatch,
    #[error("the server sent an agent endpoint that is not host:port; nothing was stored")]
    Endpoint,
    #[error("the certificates from the server were refused: {0}; nothing was stored")]
    Verify(#[source] VerifyError),
    #[error(
        "{dir} gained an enrollment while this request waited for approval; nothing was changed and the new certificates were discarded; the server already shows this enrollment as delivered, so run enroll again with --replace and have it approved again"
    )]
    EnrolledMeanwhile { dir: String },
    #[error(
        "the certificates were received but could not be stored: {0}; fix the problem and run enroll again with --replace"
    )]
    Store(#[source] StoreFailure),
    #[error("cannot write to the terminal: {0}")]
    Output(#[source] io::Error),
}

pub struct EnrollOptions {
    pub server: ServerUrl,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub replace: bool,
    pub ca_pin: Option<CaPin>,
    pub state_dir: PathBuf,
    pub hostname: String,
    pub timeout: Duration,
    pub join_token: Option<JoinToken>,
}

impl EnrollOptions {
    pub fn from_args(
        args: &EnrollArgs,
        system_hostname: impl FnOnce() -> io::Result<std::ffi::OsString>,
    ) -> Result<Self, EnrollError> {
        let hostname = match &args.hostname {
            Some(hostname) => hostname.clone(),
            None => {
                let raw = system_hostname().map_err(|_| EnrollError::Hostname {
                    reason: "the system call failed",
                })?;
                let text = raw.into_string().map_err(|_| EnrollError::Hostname {
                    reason: "it is not valid UTF-8",
                })?;
                parse_hostname(&text).map_err(|_| EnrollError::Hostname {
                    reason: "it is empty, too long or not visible ASCII",
                })?
            }
        };
        let join_token = args
            .token_file
            .as_deref()
            .map(|path| read_token_file(path, effective_uid()))
            .transpose()
            .map_err(EnrollError::TokenFile)?;
        Ok(Self {
            server: args.server.clone(),
            name: args.name.clone(),
            labels: args.labels.clone().unwrap_or_default().into_map(),
            replace: args.replace,
            ca_pin: args.ca_pin.clone(),
            state_dir: args.state_dir.clone(),
            hostname,
            timeout: Duration::from_secs(args.timeout_secs),
            join_token,
        })
    }
}

pub struct EnrollEnv<'a> {
    pub privileged: bool,
    pub clock: &'a dyn Clock,
    pub jitter: &'a mut (dyn FnMut() -> f64 + Send),
    pub out: &'a mut (dyn Write + Send),
    pub err: &'a mut (dyn Write + Send),
}

pub fn command(args: &EnrollArgs) -> ExitCode {
    let result = EnrollOptions::from_args(args, hostname::get).and_then(|options| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(EnrollError::Runtime)?;
        let mut out = io::stdout();
        let mut err = io::stderr();
        let mut jitter = || rand::random_range(0.0..=1.0);
        let mut env = system_env(&mut jitter, &mut out, &mut err);
        runtime.block_on(enroll(&options, &mut env))
    });
    crate::finish_on_stderr(result)
}

pub fn system_env<'a>(
    jitter: &'a mut (dyn FnMut() -> f64 + Send),
    out: &'a mut (dyn Write + Send),
    err: &'a mut (dyn Write + Send),
) -> EnrollEnv<'a> {
    EnrollEnv {
        privileged: running_as_root(),
        clock: &SystemClock,
        jitter,
        out,
        err,
    }
}

pub async fn enroll(options: &EnrollOptions, env: &mut EnrollEnv<'_>) -> Result<(), EnrollError> {
    let (state, _lock) = StateDir::prepare_enrollment(&options.state_dir, env.privileged)
        .map_err(EnrollError::Prepare)?;
    if state.holds_enrollment().map_err(EnrollError::Prepare)? && !options.replace {
        return Err(EnrollError::AlreadyEnrolled {
            dir: state.path().display().to_string(),
        });
    }
    let tls_key = TlsKey::generate()?;
    let host_key = HostKey::generate()?;
    let client = EnrollClient::new(&options.server).map_err(EnrollError::Request)?;
    let deadline = env
        .clock
        .now()
        .checked_add(options.timeout)
        .unwrap_or_else(|| env.clock.now());
    let mut request = EnrollRequest {
        name: options.name.clone(),
        labels: options.labels.clone(),
        hostname: options.hostname.clone(),
        tls_public_key: tls_key.spki_base64(),
        ssh_host_public_key: host_key.public_line()?,
        replace: options.replace,
        agent_version: AGENT_VERSION.to_owned(),
        join_token: options
            .join_token
            .as_ref()
            .map(|token| token.expose().to_owned()),
    };
    let answered = client.enroll(&request).await;
    if let Some(mut sent) = request.join_token.take() {
        sent.zeroize();
    }
    let response = answered.map_err(|error| match error {
        CallError::TooManyRequests => EnrollError::RateLimited,
        CallError::Status { status: 409, code } if code == "name_taken" => EnrollError::NameTaken,
        CallError::Status { status: 403, code } if code == "join_token_refused" => {
            EnrollError::TokenRefused
        }
        other => EnrollError::Request(other),
    })?;
    match (&response.code, &options.join_token) {
        (Some(code), _) => {
            if !is_showable_code(code) {
                return Err(EnrollError::BadCode);
            }
            show_request(env.out, code, response.expires_at, &tls_key, &host_key)
                .map_err(EnrollError::Output)?;
            note(
                env.err,
                format_args!(
                    "waiting up to {} seconds for an administrator to approve the request",
                    options.timeout.as_secs()
                ),
            );
        }
        (None, Some(_)) => {
            show_keys(env.out, response.expires_at, &tls_key, &host_key)
                .map_err(EnrollError::Output)?;
            note(
                env.err,
                format_args!("the join token was accepted; collecting the certificates"),
            );
        }
        (None, None) => return Err(EnrollError::BadCode),
    }
    let interval = poll_interval(response.poll_interval);
    let poll = PollRequest {
        handle: response.handle.clone(),
    };
    drop(response);
    let approved = wait_for_decision(&client, &poll, interval, options, deadline, env).await?;
    drop(poll);
    let now = env.clock.now();
    let (checked, root_der) = accept(&approved, options, &tls_key, &host_key, now)?;
    let record = EnrollmentRecord {
        node_id: approved.node_id.clone(),
        name: options.name.clone(),
        server_url: options.server.as_str().to_owned(),
        agent_endpoint: approved.agent_endpoint.clone(),
        x509_not_after: checked.x509.not_after,
        ssh_not_after: checked.ssh_not_after,
        enrolled_at: unix_secs(now),
    };
    let previous = state
        .store_enrollment(
            &EnrollmentFiles {
                record: &record,
                tls_key: &tls_key,
                host_key: &host_key,
                x509_der: &checked.x509_der,
                ssh_certificate: &checked.ssh_certificate,
                ca_root_der: &root_der,
            },
            unix_secs(now),
            options.replace,
        )
        .map_err(|failure| match failure.error {
            StateError::AlreadyEnrolled { dir } => EnrollError::EnrolledMeanwhile { dir },
            _ => EnrollError::Store(failure),
        })?;
    if let Some(previous) = &previous {
        note(
            env.err,
            format_args!(
                "the previous enrollment files were moved to {}",
                previous.display()
            ),
        );
    }
    note(
        env.err,
        format_args!(
            "enrolled as node {} ({}); certificates valid until {}; start the agent with `jaunt-agent run`",
            record.node_id,
            record.name,
            format_utc(record.x509_not_after)
        ),
    );
    Ok(())
}

fn note(err: &mut (dyn Write + Send), message: fmt::Arguments<'_>) {
    drop(writeln!(err, "{message}"));
}

fn is_showable_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CODE_LEN
        && code.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn show_request(
    out: &mut (dyn Write + Send),
    code: &str,
    expires_at: i64,
    tls_key: &TlsKey,
    host_key: &HostKey,
) -> io::Result<()> {
    writeln!(out, "code:         {code}")?;
    show_keys(out, expires_at, tls_key, host_key)?;
    writeln!(
        out,
        "An administrator must run `jauntd node approve {code}` on the server and check that both fingerprints match."
    )?;
    out.flush()
}

fn show_keys(
    out: &mut (dyn Write + Send),
    expires_at: i64,
    tls_key: &TlsKey,
    host_key: &HostKey,
) -> io::Result<()> {
    writeln!(out, "tls key:      {}", tls_key.fingerprint())?;
    writeln!(out, "ssh host key: {}", host_key.fingerprint())?;
    writeln!(out, "expires at:   {}", format_utc(expires_at))?;
    out.flush()
}

pub fn poll_interval(server_secs: u32) -> Duration {
    Duration::from_secs(u64::from(server_secs)).clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
}

pub fn jittered(interval: Duration, unit_sample: f64) -> Duration {
    let fraction = if unit_sample.is_finite() {
        unit_sample.clamp(0.0, 1.0)
    } else {
        1.0
    };
    interval.mul_f64(0.8 + 0.4 * fraction)
}

async fn wait_for_decision(
    client: &EnrollClient,
    poll: &PollRequest,
    interval: Duration,
    options: &EnrollOptions,
    deadline: SystemTime,
    env: &mut EnrollEnv<'_>,
) -> Result<EnrollmentApproved, EnrollError> {
    let timed_out = EnrollError::TimedOut {
        secs: options.timeout.as_secs(),
    };
    let mut wait = jittered(interval, (env.jitter)());
    loop {
        let now = env.clock.now();
        if now >= deadline {
            return Err(timed_out);
        }
        let wake = now
            .checked_add(wait)
            .map_or(deadline, |at| at.min(deadline));
        env.clock.sleep_until(wake).await;
        if env.clock.now() >= deadline {
            return Err(timed_out);
        }
        wait = jittered(interval, (env.jitter)());
        match client.poll(poll).await {
            Ok(PollResponse::Pending) => {}
            Ok(PollResponse::Approved(approved)) => return Ok(approved),
            Ok(PollResponse::Rejected) => return Err(EnrollError::Rejected),
            Ok(PollResponse::Expired) => return Err(EnrollError::Expired),
            Ok(PollResponse::AlreadyDelivered) => return Err(EnrollError::AlreadyDelivered),
            Err(CallError::NotFound) => return Err(EnrollError::NotFound),
            Err(CallError::TooManyRequests) => wait = RATE_LIMITED_WAIT,
            Err(error) if error.is_transient() => {
                note(env.err, format_args!("polling failed ({error}); retrying"));
            }
            Err(error) => return Err(EnrollError::Poll(error)),
        }
    }
}

fn accept(
    approved: &EnrollmentApproved,
    options: &EnrollOptions,
    tls_key: &TlsKey,
    host_key: &HostKey,
    now: SystemTime,
) -> Result<(Checked, Vec<u8>), EnrollError> {
    let root_der = verify::decode_der(&approved.internal_ca_root_der)
        .ok_or(EnrollError::Verify(VerifyError::RootEncoding))?;
    if let Some(pin) = &options.ca_pin
        && !pin.matches(&root_der)
    {
        return Err(EnrollError::PinMismatch);
    }
    AgentEndpoint::parse(&approved.agent_endpoint).map_err(|_| EnrollError::Endpoint)?;
    let checked = verify::check_certificates(
        &approved.certificates,
        &root_der,
        &Expected {
            node_id: &approved.node_id,
            name: &options.name,
            tls_spki: tls_key.spki_der(),
            ssh_key: host_key.key_data(),
        },
        now,
    )
    .map_err(EnrollError::Verify)?;
    Ok((checked, root_der))
}
