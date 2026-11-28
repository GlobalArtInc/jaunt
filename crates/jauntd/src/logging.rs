use std::io;

use jaunt_audit::{AUDIT_PRIVATE_TARGET, AuditTap};
use tracing::Subscriber;
use tracing_subscriber::filter::{Directive, FilterFn, LevelFilter, ParseError, filter_fn};
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
    let private: Directive = format!("{AUDIT_PRIVATE_TARGET}=off")
        .parse()
        .map_err(LoggingError::InvalidFilter)?;
    let spec = spec.unwrap_or_default();
    EnvFilter::builder()
        .parse(spec)
        .map_err(LoggingError::InvalidFilter)?;
    let kept: Vec<&str> = spec
        .split(',')
        .filter(|directive| !reaches_private(directive))
        .collect();
    EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse(kept.join(","))
        .map(|filter| filter.add_directive(private))
        .map_err(LoggingError::InvalidFilter)
}

fn reaches_private(directive: &str) -> bool {
    let Some(open) = directive.find('[') else {
        return false;
    };
    let target = directive[..open].trim();
    target.is_empty()
        || target == AUDIT_PRIVATE_TARGET
        || AUDIT_PRIVATE_TARGET
            .strip_prefix(target)
            .is_some_and(|rest| rest.starts_with("::"))
        || target
            .strip_prefix(AUDIT_PRIVATE_TARGET)
            .is_some_and(|rest| rest.starts_with("::"))
}

fn not_private() -> FilterFn {
    filter_fn(|metadata| !metadata.target().starts_with(AUDIT_PRIVATE_TARGET))
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
        .with_filter(filter)
        .with_filter(not_private());
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
    use tracing_subscriber::Layer;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt;

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

    #[tokio::test]
    async fn private_audit_text_reaches_the_trail_and_never_the_human_log() {
        let clock = system_clock();
        let tap = AuditTap::new(clock.clone());
        let pipeline = Pipeline::new(clock, 16);
        let sink = MemorySink::new();
        pipeline.add_sink(sink.clone()).unwrap();
        tap.bind(pipeline.clone()).unwrap();
        for spec in [
            None,
            Some("trace"),
            Some("info,jaunt::audit::private=trace"),
            Some("jaunt=trace"),
        ] {
            let captured = Captured::default();
            let loud = subscriber(build_filter(spec).unwrap(), captured.clone(), Some(&tap));
            tracing::subscriber::with_default(loud, || {
                tracing::info!(
                    target: "jaunt::audit::private",
                    event = "db.query",
                    session_id = "s-1",
                    text = "SELECT card FROM wallets WHERE owner = 'ada'"
                );
                tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "abc");
            });
            let text = captured.text();
            assert!(!text.contains("wallets"), "{spec:?}: {text}");
            assert!(!text.contains("db.query"), "{spec:?}: {text}");
            assert!(text.contains("login.started"), "{spec:?}: {text}");
        }
        let unguarded = Captured::default();
        let any_filter = subscriber(
            tracing_subscriber::EnvFilter::new("trace"),
            unguarded.clone(),
            None,
        );
        let filter_only = Captured::default();
        let filtered = tracing_subscriber::Registry::default().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(filter_only.clone())
                .with_filter(build_filter(Some("trace")).unwrap()),
        );
        for (guarded, output) in [
            (
                Box::new(any_filter) as Box<dyn tracing::Subscriber + Send + Sync>,
                &unguarded,
            ),
            (Box::new(filtered), &filter_only),
        ] {
            tracing::subscriber::with_default(guarded, || {
                tracing::info!(target: "jaunt::audit::private", event = "db.error", error_message = "secret row");
                tracing::info!(target: "jaunt::control", "visible");
            });
            assert!(!output.text().contains("secret row"), "{}", output.text());
            assert!(output.text().contains("visible"), "{}", output.text());
        }
        for spec in [
            "info,jaunt::audit::private=trace",
            "info,jaunt::audit::private::child=trace",
            "info,jaunt::audit::private[{text}]=trace",
            "info,jaunt::audit::private[{text}]=trace,jaunt::audit::private=trace",
            "info,jaunt::audit[{text}]=trace",
            "info,jaunt[{event}]=trace",
            "info,[{text}]=trace",
            "info,jaunt::audit::private::child[{text}]=trace",
        ] {
            for guarded_by_layer in [false, true] {
                let output = Captured::default();
                let filter = build_filter(Some(spec)).unwrap();
                let quiet: Box<dyn tracing::Subscriber + Send + Sync> = if guarded_by_layer {
                    Box::new(subscriber(filter, output.clone(), None))
                } else {
                    Box::new(
                        tracing_subscriber::Registry::default().with(
                            tracing_subscriber::fmt::layer()
                                .json()
                                .with_writer(output.clone())
                                .with_filter(filter),
                        ),
                    )
                };
                tracing::subscriber::with_default(quiet, || {
                    tracing::info!(target: "jaunt::audit::private", event = "db.query", text = "secret row");
                    tracing::info!(target: "jaunt::control", "visible");
                });
                assert!(
                    !output.text().contains("secret row"),
                    "{spec}: {}",
                    output.text()
                );
                assert!(
                    output.text().contains("visible"),
                    "{spec}: {}",
                    output.text()
                );
            }
        }
        pipeline.shutdown(std::time::Duration::from_secs(5)).await;
        let queries: Vec<_> = sink
            .events()
            .into_iter()
            .filter(|event| event.kind().name() == "db.query")
            .collect();
        assert_eq!(queries.len(), 4);
        assert_eq!(
            queries[0].text("text"),
            Some("SELECT card FROM wallets WHERE owner = 'ada'")
        );
    }

    #[test]
    fn only_span_and_field_filters_that_cover_the_private_target_are_left_out() {
        for (directive, reaches) in [
            ("jaunt::audit::private[{text}]=trace", true),
            ("jaunt::audit[{text}]=trace", true),
            ("jaunt[x]=debug", true),
            ("[{text}]=trace", true),
            ("jaunt::audit::private::child[{text}]=trace", true),
            ("jaunt::audit::privately[{text}]=trace", false),
            ("jaunt::control[{text}]=trace", false),
            ("jaunt::audit::private=trace", false),
            ("debug", false),
        ] {
            assert_eq!(super::reaches_private(directive), reaches, "{directive}");
        }
        assert!(build_filter(Some("jaunt::control[{text}]=trace")).is_ok());
    }

    #[test]
    fn an_empty_filter_means_info_and_a_malformed_one_is_an_error() {
        assert!(build_filter(Some("")).is_ok());
        assert!(build_filter(Some("warn,jaunt::audit=info")).is_ok());
        assert!(build_filter(Some("jaunt[=debug")).is_err());
    }
}
