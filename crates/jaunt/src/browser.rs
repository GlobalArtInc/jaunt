use std::io;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use url::Url;

const EARLY_EXIT_WINDOW: Duration = Duration::from_secs(2);
const EARLY_EXIT_POLL: Duration = Duration::from_millis(25);

#[derive(Debug, thiserror::Error)]
pub enum BrowserError {
    #[error("cannot start {program}: {source}")]
    Launch {
        program: &'static str,
        source: io::Error,
    },
    #[error("{program} reported a failure")]
    Failed { program: &'static str },
}

pub trait BrowserOpener {
    fn open(&self, url: &Url) -> Result<(), BrowserError>;
}

impl<F> BrowserOpener for F
where
    F: Fn(&Url) -> Result<(), BrowserError>,
{
    fn open(&self, url: &Url) -> Result<(), BrowserError> {
        self(url)
    }
}

pub struct SystemBrowser;

impl SystemBrowser {
    const PROGRAM: &'static str = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
}

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &Url) -> Result<(), BrowserError> {
        let program = SystemBrowser::PROGRAM;
        let mut child = Command::new(program)
            .arg(url.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| BrowserError::Launch { program, source })?;
        let deadline = Instant::now() + EARLY_EXIT_WINDOW;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) | Err(_) => return Err(BrowserError::Failed { program }),
                Ok(None) => thread::sleep(EARLY_EXIT_POLL),
            }
        }
        let reaper = thread::Builder::new()
            .name("jaunt-browser".to_owned())
            .spawn(move || drop(child.wait()));
        drop(reaper);
        Ok(())
    }
}
