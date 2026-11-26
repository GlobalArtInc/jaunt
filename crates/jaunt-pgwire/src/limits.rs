use thiserror::Error;

pub const DEFAULT_MAX_DATA_MESSAGE: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_STATEMENT_MESSAGE: usize = 1024 * 1024;
pub const DEFAULT_MAX_STARTUP_MESSAGE: usize = 16 * 1024;
pub const DEFAULT_MAX_STARTUP_PARAMETERS: usize = 64;
pub const DEFAULT_MAX_PENDING: usize = 2 * 1024 * 1024;
pub const MIN_STATEMENT_MESSAGE_LIMIT: usize = 1024;
pub const MIN_STARTUP_MESSAGE_LIMIT: usize = 268;

const WIRE_MAXIMUM: usize = i32::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_data_message: usize,
    pub max_statement_message: usize,
    pub max_startup_message: usize,
    pub max_startup_parameters: usize,
    pub max_pending: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_data_message: DEFAULT_MAX_DATA_MESSAGE,
            max_statement_message: DEFAULT_MAX_STATEMENT_MESSAGE,
            max_startup_message: DEFAULT_MAX_STARTUP_MESSAGE,
            max_startup_parameters: DEFAULT_MAX_STARTUP_PARAMETERS,
            max_pending: DEFAULT_MAX_PENDING,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum LimitsError {
    #[error("{limit} is below its minimum of {minimum}")]
    BelowMinimum { limit: &'static str, minimum: usize },
    #[error("{limit} is above the largest length the protocol can carry")]
    AboveWireMaximum { limit: &'static str },
    #[error("max_pending must hold a whole buffered message: at least {required} bytes")]
    PendingTooSmall { required: usize },
}

impl Limits {
    pub fn validate(&self) -> Result<(), LimitsError> {
        for (limit, value, minimum) in [
            ("max_data_message", self.max_data_message, 4),
            (
                "max_statement_message",
                self.max_statement_message,
                MIN_STATEMENT_MESSAGE_LIMIT,
            ),
            (
                "max_startup_message",
                self.max_startup_message,
                MIN_STARTUP_MESSAGE_LIMIT,
            ),
            ("max_startup_parameters", self.max_startup_parameters, 1),
        ] {
            if value < minimum {
                return Err(LimitsError::BelowMinimum { limit, minimum });
            }
            if value > WIRE_MAXIMUM {
                return Err(LimitsError::AboveWireMaximum { limit });
            }
        }
        let required = (self.max_statement_message + 1).max(self.max_startup_message);
        if self.max_pending < required {
            return Err(LimitsError::PendingTooSmall { required });
        }
        Ok(())
    }
}
