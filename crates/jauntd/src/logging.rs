use std::io;

use jaunt_audit::AuditTap;
use tracing::Subscriber;
use tracing_subscriber::filter::{LevelFilter, ParseError};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

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

pub fn subscriber<W>(
    filter: EnvFilter,
    writer: W,
    audit: Option<&AuditTap>,
) -> impl Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let human = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_filter(filter);
    Registry::default()
        .with(human)
        .with(audit.map(AuditTap::layer))
}

pub fn init(env: EnvLookup<'_>, audit: &AuditTap) -> Result<(), LoggingError> {
    let spec = env(FILTER_VAR)
        .map(|value| value.into_string())
        .transpose()
        .map_err(|_| LoggingError::FilterNotUnicode)?;
    let filter = build_filter(spec.as_deref())?;
    tracing::subscriber::set_global_default(subscriber(filter, io::stderr, Some(audit)))
        .map_err(|_| LoggingError::AlreadyInstalled)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use jaunt_audit::{AuditTap, MemorySink, Pipeline, system_clock};
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
        let default = subscriber(build_filter(None).unwrap(), captured.clone(), None);
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
        let debug = subscriber(build_filter(Some("debug")).unwrap(), verbose.clone(), None);
        tracing::subscriber::with_default(debug, || {
            tracing::debug!(target: "jaunt::control", "shown when asked for");
        });
        assert!(verbose.text().contains("shown when asked for"));
    }

    #[tokio::test]
    async fn audit_capture_does_not_depend_on_the_human_log_filter() {
        let clock = system_clock();
        let tap = AuditTap::new(clock.clone());
        let pipeline = Pipeline::new(clock, 16);
        let sink = MemorySink::new();
        pipeline.add_sink(sink.clone()).unwrap();
        tap.bind(pipeline.clone()).unwrap();
        let captured = Captured::default();
        let quiet = subscriber(
            build_filter(Some("error")).unwrap(),
            captured.clone(),
            Some(&tap),
        );

        tracing::subscriber::with_default(quiet, || {
            tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "abc");
            tracing::info!(target: "jaunt::control", "not an audit event");
        });
        pipeline.shutdown(std::time::Duration::from_secs(5)).await;

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind().name(), "login.started");
        assert_eq!(events[0].text("login_id"), Some("abc"));
        assert_eq!(captured.text(), "");
    }

    #[test]
    fn an_empty_filter_means_info_and_a_malformed_one_is_an_error() {
        assert!(build_filter(Some("")).is_ok());
        assert!(build_filter(Some("warn,jaunt::audit=info")).is_ok());
        assert!(build_filter(Some("jaunt[=debug")).is_err());
    }
}
