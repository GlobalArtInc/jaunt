use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jaunt_policy::{PolicyHandle, ReloadOutcome, Watcher, watch};
use tracing::Dispatch;

const POLICY_DIR_MODE: u32 = 0o750;
const PERMISSION_BITS: u32 = 0o777;
const GROUP_OR_OTHERS_WRITE: u32 = 0o022;
const REPORTED_ERRORS: usize = 3;
const MAX_ERROR_CHARS: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("cannot create the policy directory {}: {source}", path.display())]
    CreateDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the policy in {} is invalid:{}", path.display(), listed(.messages))]
    Invalid {
        path: PathBuf,
        messages: Vec<String>,
    },
}

fn listed(messages: &[String]) -> String {
    messages
        .iter()
        .map(|message| format!("\n  {message}"))
        .collect()
}

fn ensure_dir(dir: &Path) -> Result<bool, PolicyError> {
    let failed = |source| PolicyError::CreateDir {
        path: dir.to_path_buf(),
        source,
    };
    match DirBuilder::new().mode(POLICY_DIR_MODE).create(dir) {
        Ok(()) => {
            fs::set_permissions(dir, fs::Permissions::from_mode(POLICY_DIR_MODE))
                .map_err(failed)?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(failed(err)),
    }
}

pub fn load_at_startup(dir: &Path) -> Result<PolicyHandle, PolicyError> {
    let created = ensure_dir(dir)?;
    let handle = PolicyHandle::empty();
    let outcome = handle.reload(dir);
    if !outcome.applied {
        return Err(PolicyError::Invalid {
            path: dir.to_path_buf(),
            messages: outcome.errors,
        });
    }
    if !created {
        warn_if_writable_by_others(dir);
    }
    let policy = handle.snapshot();
    if policy.role_count() == 0 {
        tracing::warn!(
            target: "jaunt::daemon",
            path = %dir.display(),
            created,
            "the policy is empty and denies everything"
        );
    }
    tracing::info!(
        target: "jaunt::daemon",
        path = %dir.display(),
        policy_hash = policy.hash(),
        roles = policy.role_count(),
        "policy loaded"
    );
    Ok(handle)
}

fn warn_if_writable_by_others(dir: &Path) {
    match fs::metadata(dir) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode() & PERMISSION_BITS;
            if mode & GROUP_OR_OTHERS_WRITE != 0 {
                tracing::warn!(
                    target: "jaunt::daemon",
                    path = %dir.display(),
                    mode = format_args!("{mode:03o}"),
                    "the policy directory is writable by group or others"
                );
            }
        }
        Err(err) => tracing::warn!(
            target: "jaunt::daemon",
            path = %dir.display(),
            error = %err,
            "cannot inspect the permissions of the policy directory"
        ),
    }
}

pub fn start_watcher(handle: PolicyHandle, dir: PathBuf, interval: Duration) -> Watcher {
    let dispatch = tracing::dispatcher::get_default(Dispatch::clone);
    watch(handle, dir, interval, move |outcome| {
        tracing::dispatcher::with_default(&dispatch, || audit_reload(outcome));
    })
}

pub async fn stop_watcher(watcher: Watcher) {
    if let Err(err) = tokio::task::spawn_blocking(move || watcher.stop()).await {
        tracing::warn!(target: "jaunt::daemon", error = %err, "stopping the policy watcher failed");
    }
}

fn truncated(message: &str) -> String {
    message.chars().take(MAX_ERROR_CHARS).collect()
}

fn audit_reload(outcome: &ReloadOutcome) {
    if outcome.applied {
        tracing::info!(
            target: "jaunt::audit",
            event = "policy.reload",
            applied = true,
            hash = outcome.hash.as_deref(),
            error_count = outcome.errors.len()
        );
        return;
    }
    let shown: Vec<String> = outcome
        .errors
        .iter()
        .take(REPORTED_ERRORS)
        .map(|message| truncated(message))
        .collect();
    let error = |index: usize| shown.get(index).map(String::as_str);
    tracing::warn!(
        target: "jaunt::audit",
        event = "policy.reload",
        applied = false,
        error_count = outcome.errors.len(),
        error_1 = error(0),
        error_2 = error(1),
        error_3 = error(2)
    );
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use jaunt_policy::{PolicySet, ReloadOutcome};
    use tracing_subscriber::fmt::MakeWriter;

    use super::{PolicyError, audit_reload, load_at_startup, start_watcher};
    use crate::logging::{build_filter, subscriber};

    const TICK: Duration = Duration::from_millis(20);
    const DEADLINE: Duration = Duration::from_secs(5);
    const CHILD_DIR_VAR: &str = "JAUNTD_POLICY_TEST_DIR";
    const CHILD_TEST: &str =
        "policy::tests::a_missing_directory_is_created_with_mode_0750_under_a_restrictive_umask";
    const DENIES_EVERYTHING: &str = "denies everything";
    const WRITABLE_WARNING: &str = "writable by group or others";

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

    fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
        let captured = Captured::default();
        let guard = tracing::subscriber::set_default(subscriber(
            build_filter(None).unwrap(),
            captured.clone(),
        ));
        (captured, guard)
    }

    fn role(login: &str) -> String {
        format!(
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: ops }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{login}] }}\n"
        )
    }

    const INVALID_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { users: [contents-marker@example.com] }\n  bogus: 1\n";

    fn overwrite(dir: &Path, name: &str, content: &str) {
        let temporary = dir.join(format!(".{name}.tmp"));
        fs::write(&temporary, content).unwrap();
        fs::rename(&temporary, dir.join(name)).unwrap();
    }

    fn wait_until(what: &str, condition: impl Fn() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(started.elapsed() < DEADLINE, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn reload_events(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| line.contains("\"event\":\"policy.reload\""))
            .collect()
    }

    #[test]
    fn a_valid_directory_is_loaded_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), role("deploy")).unwrap();
        let (captured, _guard) = capture();

        let handle = load_at_startup(dir.path()).unwrap();

        let policy = handle.snapshot();
        assert_eq!(policy.role_count(), 1);
        assert_ne!(policy.hash(), PolicySet::empty().hash());
        let text = captured.text();
        assert!(text.contains("\"roles\":1"), "{text}");
        assert!(text.contains(policy.hash()), "{text}");
        assert!(!text.contains(DENIES_EVERYTHING), "{text}");
    }

    #[test]
    fn a_policy_with_access_tests_but_no_roles_is_reported_as_denying_everything() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("tests.yaml"),
            "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: alice@example.com, node: { env: prod }, login: root, expect: deny }\n",
        )
        .unwrap();
        let (captured, _guard) = capture();

        let handle = load_at_startup(dir.path()).unwrap();

        let policy = handle.snapshot();
        assert!(!policy.is_empty());
        assert_eq!(policy.role_count(), 0);
        let text = captured.text();
        assert!(text.contains(DENIES_EVERYTHING), "{text}");
        assert!(text.contains("\"roles\":0"), "{text}");
    }

    #[test]
    fn an_existing_directory_writable_by_group_or_others_is_reported_but_accepted() {
        for (mode, reported) in [
            (0o750, false),
            (0o700, false),
            (0o755, false),
            (0o770, true),
            (0o752, true),
            (0o777, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let policy_dir = dir.path().join("policy");
            fs::create_dir(&policy_dir).unwrap();
            fs::write(policy_dir.join("roles.yaml"), role("deploy")).unwrap();
            fs::set_permissions(&policy_dir, fs::Permissions::from_mode(mode)).unwrap();
            let (captured, _guard) = capture();

            let handle = load_at_startup(&policy_dir).unwrap();

            assert_eq!(handle.snapshot().role_count(), 1, "{mode:o}");
            let text = captured.text();
            assert_eq!(text.contains(WRITABLE_WARNING), reported, "{mode:o} {text}");
            if reported {
                assert!(text.contains(&format!("\"mode\":\"{mode:03o}\"")), "{text}");
            }
        }
    }

    #[test]
    fn a_missing_directory_is_created_with_mode_0750_under_a_restrictive_umask() {
        if let Some(dir) = std::env::var_os(CHILD_DIR_VAR) {
            let policy_dir = Path::new(&dir).join("policy");
            load_at_startup(&policy_dir).unwrap();
            assert_eq!(mode_of(&policy_dir), 0o750);
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new("sh")
            .args([
                "-c",
                "umask 077 && exec \"$0\" --exact \"$1\" --test-threads=1",
            ])
            .arg(std::env::current_exe().unwrap())
            .arg(CHILD_TEST)
            .env(CHILD_DIR_VAR, dir.path())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(mode_of(&dir.path().join("policy")), 0o750);
    }

    #[test]
    fn an_existing_empty_directory_is_a_valid_deny_all_policy() {
        let dir = tempfile::tempdir().unwrap();
        let (captured, _guard) = capture();

        let handle = load_at_startup(dir.path()).unwrap();

        assert!(handle.snapshot().is_empty());
        let text = captured.text();
        assert!(text.contains(DENIES_EVERYTHING), "{text}");
        assert!(text.contains("\"created\":false"), "{text}");
        assert!(text.contains(PolicySet::empty().hash()), "{text}");
    }

    #[test]
    fn a_missing_directory_is_created_with_mode_0750_and_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        let (captured, _guard) = capture();

        let handle = load_at_startup(&policy_dir).unwrap();

        assert_eq!(mode_of(&policy_dir), 0o750);
        assert!(handle.snapshot().is_empty());
        let text = captured.text();
        assert!(text.contains(DENIES_EVERYTHING), "{text}");
        assert!(text.contains("\"created\":true"), "{text}");
    }

    #[test]
    fn an_invalid_policy_is_a_startup_error_that_lists_the_messages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), INVALID_ROLE).unwrap();

        let err = load_at_startup(dir.path()).err().unwrap();

        let PolicyError::Invalid { messages, .. } = &err else {
            panic!("unexpected error {err}");
        };
        assert!(!messages.is_empty());
        let shown = err.to_string();
        assert!(shown.contains(&dir.path().display().to_string()), "{shown}");
        for message in messages {
            assert!(shown.contains(message.as_str()), "{shown}");
        }
        assert!(shown.contains("bogus"), "{shown}");
    }

    #[test]
    fn a_directory_that_cannot_be_created_is_a_startup_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_at_startup(&dir.path().join("absent").join("policy"))
            .err()
            .unwrap();
        assert!(matches!(err, PolicyError::CreateDir { .. }), "{err}");
    }

    #[test]
    fn the_watcher_applies_edits_and_rejections_and_audits_both() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("roles.yaml"), role("deploy")).unwrap();
        let handle = load_at_startup(dir.path()).unwrap();
        let started_hash = handle.snapshot().hash().to_owned();
        let (captured, _guard) = capture();

        let watcher = start_watcher(handle.clone(), dir.path().to_path_buf(), TICK);
        overwrite(dir.path(), "roles.yaml", &role("ops"));
        wait_until("the edit to apply", || {
            handle.snapshot().hash() != started_hash
        });
        let applied_hash = handle.snapshot().hash().to_owned();
        wait_until("the applied audit event", || {
            captured.text().contains(&applied_hash)
        });

        overwrite(dir.path(), "roles.yaml", INVALID_ROLE);
        wait_until("the rejected audit event", || {
            captured.text().contains("\"applied\":false")
        });
        watcher.stop();

        assert_eq!(handle.snapshot().hash(), applied_hash);
        let text = captured.text();
        let events = reload_events(&text);
        let applied = events
            .iter()
            .find(|line| line.contains(&applied_hash))
            .unwrap();
        assert!(applied.contains("\"applied\":true"), "{applied}");
        assert!(applied.contains("\"target\":\"jaunt::audit\""), "{applied}");
        let rejected = events
            .iter()
            .find(|line| line.contains("\"applied\":false"))
            .unwrap();
        assert!(rejected.contains("\"error_count\":1"), "{rejected}");
        assert!(rejected.contains("\"error_1\":"), "{rejected}");
        assert!(rejected.contains("bogus"), "{rejected}");
        assert!(!rejected.contains("\"hash\""), "{rejected}");
        assert!(!text.contains("contents-marker"), "{text}");
    }

    #[test]
    fn a_rejection_reports_the_first_three_errors_cut_to_two_hundred_chars() {
        let long = "\u{e9}".repeat(300);
        let outcome = ReloadOutcome {
            applied: false,
            unchanged: false,
            hash: None,
            input_hash: Some("input".to_owned()),
            errors: (0..5).map(|index| format!("{index}{long}")).collect(),
        };
        let (captured, _guard) = capture();

        audit_reload(&outcome);

        let text = captured.text();
        assert_eq!(reload_events(&text).len(), 1, "{text}");
        assert!(text.contains("\"error_count\":5"), "{text}");
        for index in 0..3 {
            let expected = format!("{index}{}", "\u{e9}".repeat(199));
            assert!(
                text.contains(&format!("\"error_{}\":\"{expected}\"", index + 1)),
                "{text}"
            );
        }
        assert!(!text.contains("\"error_4\""), "{text}");
        assert!(!text.contains("4\u{e9}"), "{text}");
        assert!(!text.contains(&"\u{e9}".repeat(200)), "{text}");
    }
}
