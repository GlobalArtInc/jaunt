use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use super::{CHILD_PATH, Captured, MAX_TOOL_STDERR, Stdout, SystemRunner, run};
use crate::system::Runner;

const SH: &str = "/bin/sh";
const GENEROUS: Duration = Duration::from_secs(20);

#[cfg(target_os = "linux")]
const STDIN_PROBE: &str = "readlink /proc/self/fd/0 >&2; ";
#[cfg(not(target_os = "linux"))]
const STDIN_PROBE: &str =
    "if [ /dev/stdin -ef /dev/null ]; then echo /dev/null >&2; else echo other >&2; fi; ";

fn sh(script: &str) -> Vec<String> {
    vec!["-c".to_owned(), script.to_owned()]
}

#[test]
fn the_child_gets_a_clean_environment_no_stdin_and_the_root_directory() {
    let script = format!(
        r#"printf '%s|%s|%s|' "$LC_ALL" "$PATH" "${{HOME-unset}}" >&2; {STDIN_PROBE}pwd >&2; exit 3"#
    );
    let exit = SystemRunner
        .run(Path::new(SH), &sh(&script), GENEROUS)
        .unwrap();
    assert_eq!(exit.code, Some(3));
    assert!(!exit.timed_out);
    assert_eq!(
        String::from_utf8(exit.stderr).unwrap(),
        format!("C|{CHILD_PATH}|unset|/dev/null\n/\n")
    );
}

#[test]
fn a_child_past_its_timeout_is_killed_and_reaped_and_only_then_marked_timed_out() {
    let started = Instant::now();
    let finished = run(
        Path::new(SH),
        &sh("sleep 30"),
        Duration::from_millis(300),
        Stdout::Discard,
    )
    .unwrap();
    assert!(finished.timed_out);
    assert_eq!(finished.code, None);
    assert!(started.elapsed() < GENEROUS, "{:?}", started.elapsed());

    let quick = run(Path::new(SH), &sh("exit 0"), GENEROUS, Stdout::Discard).unwrap();
    assert!(!quick.timed_out);
    assert_eq!(quick.code, Some(0));
}

#[test]
fn a_timed_out_child_is_reaped_before_run_returns() {
    let dir = tempfile::tempdir().unwrap();
    let pid_file = dir.path().join("pid");
    let args = vec![
        "-c".to_owned(),
        r#"echo $$ > "$1"; sleep 30"#.to_owned(),
        "sh".to_owned(),
        pid_file.to_str().unwrap().to_owned(),
    ];
    let finished = run(
        Path::new(SH),
        &args,
        Duration::from_secs(2),
        Stdout::Discard,
    )
    .unwrap();
    assert!(finished.timed_out);
    let pid: i32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_reaped(pid);
}

#[cfg(target_os = "linux")]
fn assert_reaped(pid: i32) {
    let entry = Path::new("/proc").join(pid.to_string());
    assert!(!entry.exists(), "{entry:?} is still there");
}

#[cfg(not(target_os = "linux"))]
fn assert_reaped(pid: i32) {
    use rustix::io::Errno;
    use rustix::process::{Pid, WaitOptions, waitpid};

    let pid = Pid::from_raw(pid).unwrap();
    assert_eq!(
        waitpid(Some(pid), WaitOptions::NOHANG).map(|status| status.is_some()),
        Err(Errno::CHILD),
        "process {pid:?} was left unreaped"
    );
}

#[test]
fn captured_output_is_bounded_flagged_when_cut_and_never_blocks_the_child() {
    let finished = run(
        Path::new(SH),
        &sh("printf abcdef; printf xyz >&2"),
        GENEROUS,
        Stdout::Capture { limit: 4 },
    )
    .unwrap();
    assert_eq!(
        finished.stdout,
        Captured {
            bytes: b"abcd".to_vec(),
            truncated: true
        }
    );
    assert_eq!(
        finished.stderr,
        Captured {
            bytes: b"xyz".to_vec(),
            truncated: false
        }
    );

    let large = run(
        Path::new(SH),
        &sh("head -c 300000 /dev/zero; head -c 10000 /dev/zero >&2"),
        GENEROUS,
        Stdout::Capture { limit: 1 << 20 },
    )
    .unwrap();
    assert_eq!(large.code, Some(0));
    assert_eq!(large.stdout.bytes.len(), 300_000);
    assert!(!large.stdout.truncated);
    assert_eq!(large.stderr.bytes.len(), MAX_TOOL_STDERR);
    assert!(large.stderr.truncated);
}

#[test]
fn a_program_that_cannot_start_is_an_error_and_not_an_exit_code() {
    let error = SystemRunner
        .run(Path::new("/nonexistent/jaunt-tool"), &[], GENEROUS)
        .unwrap_err();
    assert_eq!(error.program, Path::new("/nonexistent/jaunt-tool"));
}
