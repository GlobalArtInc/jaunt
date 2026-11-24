use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use jaunt_proto::SessionPermissions;
use tokio_util::sync::CancellationToken;

#[derive(Clone, PartialEq, Eq)]
pub enum ChannelProgram {
    Shell,
    Exec(Vec<u8>),
    Subsystem(String),
}

impl fmt::Debug for ChannelProgram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shell => f.write_str("Shell"),
            Self::Exec(command) => f
                .debug_struct("Exec")
                .field("command_len", &command.len())
                .finish(),
            Self::Subsystem(name) => f.debug_tuple("Subsystem").field(name).finish(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    pub columns: u32,
    pub rows: u32,
    pub pixel_width: u32,
    pub pixel_height: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    pub term: String,
    pub size: TerminalSize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStart {
    pub program: ChannelProgram,
    pub terminal: Option<Terminal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelExit {
    Status(u32),
    Signal(String),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recording {
    Complete,
    Incomplete,
}

pub trait SessionObserver: Send {
    fn channel_start(&mut self, _channel: u32, _start: &ChannelStart) {}

    fn input(&mut self, _channel: u32, _data: &[u8]) {}

    fn output(&mut self, _channel: u32, _stream: OutputStream, _data: &[u8]) {}

    fn resize(&mut self, _channel: u32, _size: TerminalSize) {}

    fn channel_end(&mut self, _channel: u32, _exit: &ChannelExit) {}

    fn forward_open(&mut self, _channel: u32, _target: &ForwardTarget) {}

    fn forward_close(&mut self, _channel: u32) {}

    fn finish(&mut self) -> Recording {
        Recording::Complete
    }
}

pub trait ObserverFactory: Send + Sync + 'static {
    fn create(
        &self,
        session_id: &str,
        permissions: &SessionPermissions,
    ) -> Box<dyn SessionObserver>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoObserver;

impl SessionObserver for NoObserver {}

impl ObserverFactory for NoObserver {
    fn create(
        &self,
        _session_id: &str,
        _permissions: &SessionPermissions,
    ) -> Box<dyn SessionObserver> {
        Box::new(NoObserver)
    }
}

pub(crate) struct ObserverCell {
    slot: Mutex<Option<Box<dyn SessionObserver>>>,
    failed: AtomicBool,
    stop: CancellationToken,
}

impl ObserverCell {
    pub(crate) fn new(stop: CancellationToken) -> Self {
        Self {
            slot: Mutex::new(None),
            failed: AtomicBool::new(false),
            stop,
        }
    }

    pub(crate) fn create(
        &self,
        factory: &dyn ObserverFactory,
        session_id: &str,
        permissions: &SessionPermissions,
    ) -> Result<(), ObserverFailed> {
        match catch_unwind(AssertUnwindSafe(|| factory.create(session_id, permissions))) {
            Ok(observer) => {
                *self.slot() = Some(observer);
                Ok(())
            }
            Err(_) => {
                self.fail();
                Err(ObserverFailed)
            }
        }
    }

    pub(crate) fn call(&self, event: impl FnOnce(&mut dyn SessionObserver)) {
        let mut slot = self.slot();
        let Some(observer) = slot.as_mut() else {
            return;
        };
        if catch_unwind(AssertUnwindSafe(|| event(observer.as_mut()))).is_ok() {
            return;
        }
        let broken = slot.take();
        drop(slot);
        discard(broken);
        self.fail();
    }

    pub(crate) fn finish(&self) -> Recording {
        let taken = self.slot().take();
        let recording = match taken {
            Some(mut observer) => {
                let finished = catch_unwind(AssertUnwindSafe(|| observer.finish()));
                discard(Some(observer));
                finished.unwrap_or_else(|_| {
                    self.fail();
                    Recording::Incomplete
                })
            }
            None => Recording::Complete,
        };
        if self.failed() {
            Recording::Incomplete
        } else {
            recording
        }
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn fail(&self) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            tracing::error!(
                target: "jaunt::audit",
                event = "agent.ssh.observer_failed"
            );
        }
        self.stop.cancel();
    }

    fn slot(&self) -> MutexGuard<'_, Option<Box<dyn SessionObserver>>> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObserverFailed;

fn discard(observer: Option<Box<dyn SessionObserver>>) {
    if catch_unwind(AssertUnwindSafe(move || drop(observer))).is_err() {
        tracing::error!(
            target: "jaunt::audit",
            event = "agent.ssh.observer_failed",
            stage = "drop"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use jaunt_proto::SessionPermissions;
    use tokio_util::sync::CancellationToken;

    use super::{
        ChannelProgram, ObserverCell, ObserverFactory, OutputStream, Recording, SessionObserver,
    };

    struct Scripted {
        seen: Arc<Mutex<Vec<String>>>,
        panic_on_output: bool,
        finish: Recording,
    }

    impl SessionObserver for Scripted {
        fn input(&mut self, channel: u32, data: &[u8]) {
            self.seen
                .lock()
                .unwrap()
                .push(format!("in {channel} {}", data.len()));
        }

        fn output(&mut self, channel: u32, _stream: OutputStream, data: &[u8]) {
            assert!(!self.panic_on_output, "observer failure");
            self.seen
                .lock()
                .unwrap()
                .push(format!("out {channel} {}", data.len()));
        }

        fn finish(&mut self) -> Recording {
            self.finish
        }
    }

    struct Factory(Arc<Mutex<Vec<String>>>, bool, Recording);

    impl ObserverFactory for Factory {
        fn create(&self, _: &str, _: &SessionPermissions) -> Box<dyn SessionObserver> {
            Box::new(Scripted {
                seen: Arc::clone(&self.0),
                panic_on_output: self.1,
                finish: self.2,
            })
        }
    }

    const PERMISSIONS: SessionPermissions = SessionPermissions {
        pty: true,
        port_forwarding: false,
        record_input: true,
        max_duration_secs: 60,
    };

    #[test]
    fn a_panicking_observer_is_dropped_marks_the_recording_and_stops_the_session() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = CancellationToken::new();
        let cell = ObserverCell::new(stop.clone());
        cell.create(
            &Factory(Arc::clone(&seen), true, Recording::Complete),
            "s",
            &PERMISSIONS,
        )
        .unwrap();
        cell.call(|o| o.input(0, b"ab"));
        assert!(!stop.is_cancelled());
        cell.call(|o| o.output(0, OutputStream::Stdout, b"x"));
        cell.call(|o| o.input(0, b"c"));
        assert!(stop.is_cancelled());
        assert!(cell.failed());
        assert_eq!(*seen.lock().unwrap(), ["in 0 2"]);
        assert_eq!(cell.finish(), Recording::Incomplete);
    }

    #[test]
    fn the_observer_decides_whether_its_recording_is_complete() {
        for expected in [Recording::Complete, Recording::Incomplete] {
            let stop = CancellationToken::new();
            let cell = ObserverCell::new(stop.clone());
            cell.create(&Factory(Arc::default(), false, expected), "s", &PERMISSIONS)
                .unwrap();
            assert_eq!(cell.finish(), expected);
            assert!(!stop.is_cancelled());
        }
        assert_eq!(
            ObserverCell::new(CancellationToken::new()).finish(),
            Recording::Complete
        );
    }

    #[test]
    fn debug_output_hides_exec_commands() {
        let shown = format!("{:?}", ChannelProgram::Exec(b"mysql -psecret".to_vec()));
        assert_eq!(shown, "Exec { command_len: 14 }");
    }
}
