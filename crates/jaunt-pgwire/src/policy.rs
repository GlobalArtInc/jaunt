use thiserror::Error;

use crate::startup::StartupMessage;

pub const DEFAULT_ALLOWED_PARAMETERS: &[&str] = &[
    "application_name",
    "client_encoding",
    "DateStyle",
    "TimeZone",
    "IntervalStyle",
    "extra_float_digits",
    "search_path",
];
pub const DEFAULT_MAX_PARAMETERS: usize = 16;
pub const DEFAULT_MAX_PARAMETER_BYTES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 63;

const USER: &str = "user";
const DATABASE: &str = "database";
const REPLICATION: &str = "replication";
const APPLICATION_NAME: &str = "application_name";
const CLIENT_ENCODING: &str = "client_encoding";
const ALLOWED_CLIENT_ENCODINGS: &[&str] = &["UTF8", "UNICODE"];
const REPORTED_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StartupRefusal {
    #[error("replication connections are refused")]
    Replication,
    #[error("startup parameter {name:?} is not allowed")]
    ParameterNotAllowed { name: String },
    #[error("the startup message has {count} parameters, above the limit of {limit}")]
    TooManyParameters { count: usize, limit: usize },
    #[error("startup parameters take {bytes} bytes, above the limit of {limit}")]
    ParametersTooLarge { bytes: usize, limit: usize },
    #[error("only UTF-8 is allowed as the client encoding")]
    ClientEncodingNotAllowed,
    #[error("the startup message names no user")]
    MissingUser,
    #[error("the {parameter} name is longer than {limit} bytes")]
    NameTooLong {
        parameter: &'static str,
        limit: usize,
    },
    #[error("the requested user is not the authorized one")]
    UserMismatch,
    #[error("the requested database is not the authorized one")]
    DatabaseMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupRequest<'m> {
    pub user: &'m str,
    pub database: &'m str,
    pub application_name: Option<&'m str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupPolicy {
    allowed: Vec<String>,
    max_parameters: usize,
    max_parameter_bytes: usize,
}

impl Default for StartupPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_ALLOWED_PARAMETERS.iter().copied(),
            DEFAULT_MAX_PARAMETERS,
            DEFAULT_MAX_PARAMETER_BYTES,
        )
    }
}

impl StartupPolicy {
    pub fn new<I, S>(allowed: I, max_parameters: usize, max_parameter_bytes: usize) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: allowed.into_iter().map(Into::into).collect(),
            max_parameters,
            max_parameter_bytes,
        }
    }

    pub fn inspect<'m>(
        &self,
        startup: &'m StartupMessage,
    ) -> Result<StartupRequest<'m>, StartupRefusal> {
        let count = startup.parameters().count();
        if count > self.max_parameters {
            return Err(StartupRefusal::TooManyParameters {
                count,
                limit: self.max_parameters,
            });
        }
        let bytes: usize = startup
            .parameters()
            .map(|(name, value)| name.len() + value.len() + 2)
            .sum();
        if bytes > self.max_parameter_bytes {
            return Err(StartupRefusal::ParametersTooLarge {
                bytes,
                limit: self.max_parameter_bytes,
            });
        }
        for (name, _) in startup.parameters() {
            if name.eq_ignore_ascii_case(REPLICATION) {
                return Err(StartupRefusal::Replication);
            }
        }
        for (name, _) in startup.parameters() {
            if self.canonical(name).is_none() {
                return Err(StartupRefusal::ParameterNotAllowed {
                    name: reported(name),
                });
            }
        }
        if let Some(encoding) = parameter_ignoring_case(startup, CLIENT_ENCODING) {
            let allowed = ALLOWED_CLIENT_ENCODINGS
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(encoding));
            if !allowed {
                return Err(StartupRefusal::ClientEncodingNotAllowed);
            }
        }
        let user = match startup.parameter(USER) {
            Some(user) if !user.is_empty() => user,
            _ => return Err(StartupRefusal::MissingUser),
        };
        let database = match startup.parameter(DATABASE) {
            Some(database) if !database.is_empty() => database,
            _ => user,
        };
        for (parameter, value) in [(USER, user), (DATABASE, database)] {
            if value.len() > MAX_NAME_BYTES {
                return Err(StartupRefusal::NameTooLong {
                    parameter,
                    limit: MAX_NAME_BYTES,
                });
            }
        }
        Ok(StartupRequest {
            user,
            database,
            application_name: parameter_ignoring_case(startup, APPLICATION_NAME),
        })
    }

    pub fn rewrite(
        &self,
        startup: &StartupMessage,
        user: &str,
        database: &str,
    ) -> Result<StartupMessage, StartupRefusal> {
        let request = self.inspect(startup)?;
        if request.user != user {
            return Err(StartupRefusal::UserMismatch);
        }
        if request.database != database {
            return Err(StartupRefusal::DatabaseMismatch);
        }
        let mut parameters = vec![
            (USER.to_owned(), request.user.to_owned()),
            (DATABASE.to_owned(), request.database.to_owned()),
        ];
        parameters.extend(
            startup
                .parameters()
                .filter(|(name, _)| *name != USER && *name != DATABASE)
                .filter_map(|(name, value)| {
                    self.canonical(name)
                        .map(|canonical| (canonical.to_owned(), value.to_owned()))
                }),
        );
        Ok(StartupMessage::from_parts(startup.version(), parameters))
    }

    fn canonical<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        if name == USER || name == DATABASE {
            return Some(name);
        }
        if name.eq_ignore_ascii_case(USER)
            || name.eq_ignore_ascii_case(DATABASE)
            || name.eq_ignore_ascii_case(REPLICATION)
        {
            return None;
        }
        self.allowed
            .iter()
            .find(|allowed| allowed.eq_ignore_ascii_case(name))
            .map(String::as_str)
    }
}

fn parameter_ignoring_case<'m>(startup: &'m StartupMessage, name: &str) -> Option<&'m str> {
    startup
        .parameters()
        .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn reported(name: &str) -> String {
    let mut end = name.len().min(REPORTED_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_owned()
}
