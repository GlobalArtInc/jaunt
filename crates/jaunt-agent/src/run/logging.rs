use std::io;

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{LevelFilter, ParseError};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("the log filter is not valid: {0}")]
    InvalidFilter(#[source] ParseError),
    #[error("a log subscriber is already installed")]
    AlreadyInstalled,
}

pub fn build_filter(spec: Option<&str>) -> Result<EnvFilter, LoggingError> {
    EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse(spec.unwrap_or_default())
        .map_err(LoggingError::InvalidFilter)
}

pub fn subscriber<W>(filter: EnvFilter, writer: W) -> impl Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(writer)
        .finish()
}

pub fn choose_filter<'a>(
    env_spec: Option<&'a str>,
    config_level: Option<&'a str>,
) -> Option<&'a str> {
    env_spec.filter(|spec| !spec.is_empty()).or(config_level)
}

pub fn init(spec: Option<&str>) -> Result<(), LoggingError> {
    let filter = build_filter(spec)?;
    tracing::subscriber::set_global_default(subscriber(filter, io::stderr))
        .map_err(|_| LoggingError::AlreadyInstalled)
}

#[cfg(test)]
mod tests {
    use super::{build_filter, choose_filter, subscriber};
    use crate::testkit::LogCapture;

    #[test]
    fn the_environment_wins_over_the_config_and_both_default_to_info() {
        assert_eq!(choose_filter(Some("debug"), Some("warn")), Some("debug"));
        assert_eq!(choose_filter(Some(""), Some("warn")), Some("warn"));
        assert_eq!(choose_filter(None, None), None);
        assert!(build_filter(Some("jaunt[=debug")).is_err());

        let captured = LogCapture::default();
        let quiet = subscriber(build_filter(None).unwrap(), captured.clone());
        tracing::subscriber::with_default(quiet, || {
            tracing::info!(target: "jaunt::agent", refused_streams = 1, "shown");
            tracing::debug!(target: "jaunt::agent", "hidden");
        });
        let text = captured.text();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("\"refused_streams\":1"), "{text}");
    }
}
