use std::io;

use tracing::Subscriber;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::{LevelFilter, ParseError};
use tracing_subscriber::fmt::MakeWriter;

use crate::config::EnvLookup;

const FILTER_VAR: &str = "RUST_LOG";

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("{FILTER_VAR} is not valid unicode")]
    FilterNotUnicode,
    #[error("{FILTER_VAR} is not a valid log filter: {0}")]
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

pub fn init(env: EnvLookup<'_>) -> Result<(), LoggingError> {
    let spec = env(FILTER_VAR)
        .map(|value| value.into_string())
        .transpose()
        .map_err(|_| LoggingError::FilterNotUnicode)?;
    let filter = build_filter(spec.as_deref())?;
    tracing::subscriber::set_global_default(subscriber(filter, io::stderr))
        .map_err(|_| LoggingError::AlreadyInstalled)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::{build_filter, subscriber};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Captured {
        type Writer = Captured;

        fn make_writer(&self) -> Captured {
            self.clone()
        }
    }

    #[test]
    fn audit_events_reach_the_json_output_and_the_default_level_is_info() {
        let captured = Captured::default();
        let default = subscriber(build_filter(None).unwrap(), captured.clone());
        tracing::subscriber::with_default(default, || {
            tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "abc");
            tracing::debug!(target: "jaunt::control", "hidden at the default level");
        });
        let text = captured.text();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("\"target\":\"jaunt::audit\""), "{text}");
        assert!(text.contains("\"event\":\"login.started\""), "{text}");
        assert!(text.contains("\"login_id\":\"abc\""), "{text}");

        let verbose = Captured::default();
        let debug = subscriber(build_filter(Some("debug")).unwrap(), verbose.clone());
        tracing::subscriber::with_default(debug, || {
            tracing::debug!(target: "jaunt::control", "shown when asked for");
        });
        assert!(verbose.text().contains("shown when asked for"));
    }

    #[test]
    fn an_empty_filter_means_info_and_a_malformed_one_is_an_error() {
        assert!(build_filter(Some("")).is_ok());
        assert!(build_filter(Some("warn,jaunt::audit=info")).is_ok());
        assert!(build_filter(Some("jaunt[=debug")).is_err());
    }
}
