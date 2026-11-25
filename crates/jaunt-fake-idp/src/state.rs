use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::key::TestOnlySigningKey;
use crate::settings::User;

pub const CODE_TTL: Duration = Duration::from_secs(60);
pub const ID_TOKEN_TTL_SECS: u64 = 300;

pub struct Settings {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub users: Vec<User>,
    pub session_ttl: Duration,
}

pub(crate) struct Grant {
    pub(crate) challenge: String,
    pub(crate) nonce: Option<String>,
    pub(crate) redirect_uri: String,
    pub(crate) user: User,
}

struct Issued {
    grant: Grant,
    expires: Instant,
}

struct Session {
    user: User,
    expires: Instant,
}

#[derive(Default)]
struct Tables {
    grants: HashMap<String, Issued>,
    sessions: HashMap<String, Session>,
}

pub struct State {
    pub(crate) settings: Settings,
    pub(crate) key: TestOnlySigningKey,
    tables: Mutex<Tables>,
}

fn random_token() -> String {
    let bytes: [u8; 24] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl State {
    pub fn new(settings: Settings) -> State {
        State {
            settings,
            key: TestOnlySigningKey::generate(),
            tables: Mutex::new(Tables::default()),
        }
    }

    pub(crate) fn user_for_hint(&self, hint: &str) -> Option<User> {
        self.settings
            .users
            .iter()
            .find(|user| user.login_hint == hint)
            .cloned()
    }

    pub(crate) fn open_session(&self, user: User, now: Instant) -> String {
        let id = random_token();
        let mut tables = self.lock();
        tables.sessions.retain(|_, session| session.expires > now);
        tables.sessions.insert(
            id.clone(),
            Session {
                user,
                expires: now + self.settings.session_ttl,
            },
        );
        id
    }

    pub(crate) fn session_user(&self, id: &str, now: Instant) -> Option<User> {
        let tables = self.lock();
        let session = tables.sessions.get(id)?;
        (session.expires > now).then(|| session.user.clone())
    }

    pub(crate) fn issue_code(&self, grant: Grant, now: Instant) -> String {
        let code = random_token();
        let mut tables = self.lock();
        tables.grants.retain(|_, issued| issued.expires > now);
        tables.grants.insert(
            code.clone(),
            Issued {
                grant,
                expires: now + CODE_TTL,
            },
        );
        code
    }

    pub(crate) fn take_code(&self, code: &str, now: Instant) -> Option<Grant> {
        let issued = self.lock().grants.remove(code)?;
        (issued.expires > now).then_some(issued.grant)
    }

    fn lock(&self) -> MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
