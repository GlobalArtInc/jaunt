use std::ffi::OsString;
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime};

use crate::agent::SshAgent;
use crate::browser::SystemBrowser;
use crate::consent::TerminalPrompt;
use crate::ensure::{
    EnsureError, Freshness, RenewOptions, Renewed, check, lock_renewal, renew_deadline,
    renew_with_lock, unix_now,
};
use crate::lock::ProfileLock;
use crate::login::LoginPorts;
use crate::profile::ProfileName;
use crate::service_dial::{
    ClientIdentity, Prepared, ServiceSetupError, UnusableIdentity, service_gate_for,
};
use crate::store::ProfileStore;
use crate::user_x509::{X509Error, ensure_x509, load_identity};

pub const WAIT_NOTICE_AFTER: Duration = Duration::from_secs(1);
pub const WAIT_NOTICE: &str = "waiting for another sign-in of this profile to finish";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("sign-in needed for profile `{profile}`: run `{hint}`")]
    SignInNeeded { profile: ProfileName, hint: String },
    #[error(transparent)]
    Ensure(#[from] EnsureError),
    #[error(transparent)]
    X509(#[from] X509Error),
    #[error(transparent)]
    Unusable(#[from] UnusableIdentity),
    #[error(transparent)]
    Setup(#[from] ServiceSetupError),
}

pub struct ProfileIdentity {
    pub renew: RenewOptions,
    pub interactive: bool,
    pub ssh_auth_sock: Option<OsString>,
    pub clock: fn() -> SystemTime,
}

impl ProfileIdentity {
    pub fn store(&self) -> ProfileStore {
        ProfileStore::new(&self.renew.home, &self.renew.profile)
    }

    pub fn load(&self) -> Result<Prepared, IdentityError> {
        self.load_with(&mut io::stderr(), None)
    }

    pub fn load_at_start(&self) -> Result<Prepared, IdentityError> {
        self.load_with(&mut io::stderr(), Some(WAIT_NOTICE_AFTER))
    }

    pub fn load_with(
        &self,
        notices: &mut dyn Write,
        announce_after: Option<Duration>,
    ) -> Result<Prepared, IdentityError> {
        let options = &self.renew;
        let store = self.store();
        let deadline = renew_deadline(options)?;
        let lock = self.lock(deadline, announce_after, notices)?;
        let outcome = self.load_locked(&store, &lock, deadline, notices);
        drop(lock);
        outcome
    }

    fn lock(
        &self,
        deadline: Instant,
        announce_after: Option<Duration>,
        notices: &mut dyn Write,
    ) -> Result<ProfileLock, IdentityError> {
        let options = &self.renew;
        if let Some(after) = announce_after {
            let quiet_until = Instant::now()
                .checked_add(after)
                .map_or(deadline, |at| at.min(deadline));
            match lock_renewal(options, quiet_until, &mut io::sink()) {
                Ok(lock) => return Ok(lock),
                Err(EnsureError::TimedOut { .. }) if Instant::now() < deadline => {
                    drop(writeln!(notices, "jaunt: {WAIT_NOTICE}"));
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok(lock_renewal(options, deadline, &mut io::sink())?)
    }

    fn load_locked(
        &self,
        store: &ProfileStore,
        lock: &ProfileLock,
        deadline: Instant,
        notices: &mut dyn Write,
    ) -> Result<Prepared, IdentityError> {
        let options = &self.renew;
        let now = unix_now(&self.clock)?;
        match check(store, now).map_err(EnsureError::Store)? {
            Freshness::Fresh => {}
            Freshness::NotSignedIn => return Err(options.not_signed_in(store).into()),
            Freshness::Stale if !self.interactive => {
                return Err(IdentityError::SignInNeeded {
                    profile: options.profile.clone(),
                    hint: options.login_hint(),
                });
            }
            Freshness::Stale => self.sign_in(lock, deadline, notices)?,
        }
        let now = unix_now(&self.clock)?;
        let certificate = ensure_x509(store, lock, now)?;
        let identity = ClientIdentity::from_x509(&load_identity(store, lock, &certificate)?)?;
        let gate = service_gate_for(store, &options.profile, now)?;
        Ok(Prepared { gate, identity })
    }

    fn sign_in(
        &self,
        lock: &ProfileLock,
        deadline: Instant,
        notices: &mut dyn Write,
    ) -> Result<(), IdentityError> {
        let agent = SshAgent::new(self.ssh_auth_sock.clone());
        let mut ports = LoginPorts {
            browser: &SystemBrowser,
            agent: &agent,
            clock: &self.clock,
            notices,
            consent: &TerminalPrompt,
        };
        if let Renewed::SignedIn(report) = renew_with_lock(&self.renew, &mut ports, deadline, lock)?
        {
            for note in report.warnings() {
                drop(writeln!(ports.notices, "jaunt: {note}"));
            }
            drop(writeln!(ports.notices, "jaunt: {}", report.summary()));
        }
        Ok(())
    }
}
