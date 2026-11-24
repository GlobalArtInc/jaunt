use std::time::Duration;

use h2::PingPong;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;
pub const DEFAULT_STREAM_WINDOW: u32 = 256 * 1024;
pub const DEFAULT_CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
pub const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

pub const MAX_TIMER: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_STREAM_LIMIT: u32 = 1 << 20;
pub const MAX_WINDOW: u32 = 0x7fff_ffff;
pub const MIN_HEADER_LIST_SIZE: u32 = 1024;
pub const MAX_HEADER_LIST_SIZE: u32 = 1 << 20;
pub const MAX_HANDSHAKING_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OptionsError {
    #[error("max_concurrent_streams is zero or too large")]
    StreamLimit,
    #[error("stream_window is zero or too large")]
    StreamWindow,
    #[error("connection_window is zero or too large")]
    ConnectionWindow,
    #[error("max_header_list_size is out of range")]
    HeaderListSize,
    #[error("keepalive interval is zero or too long")]
    KeepaliveInterval,
    #[error("keepalive timeout is zero or too long")]
    KeepaliveTimeout,
    #[error("handshake timeout is zero or too long")]
    HandshakeTimeout,
    #[error("hello timeout is zero or too long")]
    HelloTimeout,
    #[error("open timeout is zero or too long")]
    OpenTimeout,
    #[error("close grace is too long")]
    CloseGrace,
    #[error("handshake limit is zero or too large")]
    HandshakeLimit,
    #[error("backoff initial delay is zero or longer than the maximum")]
    BackoffInitial,
    #[error("backoff maximum delay is too long")]
    BackoffMax,
    #[error("backoff reset threshold is too long")]
    BackoffResetAfter,
}

pub(crate) fn timer_in_range(value: Duration) -> bool {
    !value.is_zero() && value <= MAX_TIMER
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive {
    pub interval: Duration,
    pub timeout: Duration,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(20),
            timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelOptions {
    pub max_concurrent_streams: u32,
    pub stream_window: u32,
    pub connection_window: u32,
    pub max_header_list_size: u32,
    pub keepalive: Keepalive,
    pub handshake_timeout: Duration,
    pub hello_timeout: Duration,
    pub open_timeout: Duration,
    pub close_grace: Duration,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self {
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            stream_window: DEFAULT_STREAM_WINDOW,
            connection_window: DEFAULT_CONNECTION_WINDOW,
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            keepalive: Keepalive::default(),
            handshake_timeout: Duration::from_secs(10),
            hello_timeout: Duration::from_secs(5),
            open_timeout: Duration::from_secs(10),
            close_grace: Duration::from_secs(2),
        }
    }
}

impl TunnelOptions {
    pub fn validate(&self) -> Result<(), OptionsError> {
        if self.max_concurrent_streams == 0 || self.max_concurrent_streams > MAX_STREAM_LIMIT {
            return Err(OptionsError::StreamLimit);
        }
        if self.stream_window == 0 || self.stream_window > MAX_WINDOW {
            return Err(OptionsError::StreamWindow);
        }
        if self.connection_window == 0 || self.connection_window > MAX_WINDOW {
            return Err(OptionsError::ConnectionWindow);
        }
        if !(MIN_HEADER_LIST_SIZE..=MAX_HEADER_LIST_SIZE).contains(&self.max_header_list_size) {
            return Err(OptionsError::HeaderListSize);
        }
        if !timer_in_range(self.keepalive.interval) {
            return Err(OptionsError::KeepaliveInterval);
        }
        if !timer_in_range(self.keepalive.timeout) {
            return Err(OptionsError::KeepaliveTimeout);
        }
        if !timer_in_range(self.handshake_timeout) {
            return Err(OptionsError::HandshakeTimeout);
        }
        if !timer_in_range(self.hello_timeout) {
            return Err(OptionsError::HelloTimeout);
        }
        if !timer_in_range(self.open_timeout) {
            return Err(OptionsError::OpenTimeout);
        }
        if self.close_grace > MAX_TIMER {
            return Err(OptionsError::CloseGrace);
        }
        Ok(())
    }

    pub(crate) fn advertised_stream_limit(&self) -> u32 {
        self.max_concurrent_streams.saturating_add(1)
    }
}

pub(crate) async fn keepalive(mut pings: PingPong, settings: Keepalive, cancel: CancellationToken) {
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(settings.interval) => {}
        }
        let answered = tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            outcome = tokio::time::timeout(settings.timeout, pings.ping(h2::Ping::opaque())) => {
                matches!(outcome, Ok(Ok(_)))
            }
        };
        if !answered {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Mutation = fn(&mut TunnelOptions);

    #[test]
    fn defaults_are_valid() {
        assert_eq!(TunnelOptions::default().validate(), Ok(()));
    }

    #[test]
    fn every_numeric_option_rejects_its_bad_values() {
        let day_and_a_second = MAX_TIMER + Duration::from_secs(1);
        let cases: Vec<(&str, Mutation, OptionsError)> = vec![
            (
                "zero stream limit",
                |o| o.max_concurrent_streams = 0,
                OptionsError::StreamLimit,
            ),
            (
                "huge stream limit",
                |o| o.max_concurrent_streams = MAX_STREAM_LIMIT + 1,
                OptionsError::StreamLimit,
            ),
            (
                "zero stream window",
                |o| o.stream_window = 0,
                OptionsError::StreamWindow,
            ),
            (
                "huge stream window",
                |o| o.stream_window = MAX_WINDOW + 1,
                OptionsError::StreamWindow,
            ),
            (
                "zero connection window",
                |o| o.connection_window = 0,
                OptionsError::ConnectionWindow,
            ),
            (
                "huge connection window",
                |o| o.connection_window = MAX_WINDOW + 1,
                OptionsError::ConnectionWindow,
            ),
            (
                "tiny header list",
                |o| o.max_header_list_size = MIN_HEADER_LIST_SIZE - 1,
                OptionsError::HeaderListSize,
            ),
            (
                "huge header list",
                |o| o.max_header_list_size = MAX_HEADER_LIST_SIZE + 1,
                OptionsError::HeaderListSize,
            ),
            (
                "zero keepalive interval",
                |o| o.keepalive.interval = Duration::ZERO,
                OptionsError::KeepaliveInterval,
            ),
            (
                "endless keepalive interval",
                |o| o.keepalive.interval = Duration::MAX,
                OptionsError::KeepaliveInterval,
            ),
            (
                "zero keepalive timeout",
                |o| o.keepalive.timeout = Duration::ZERO,
                OptionsError::KeepaliveTimeout,
            ),
            (
                "endless keepalive timeout",
                |o| o.keepalive.timeout = Duration::MAX,
                OptionsError::KeepaliveTimeout,
            ),
            (
                "zero handshake timeout",
                |o| o.handshake_timeout = Duration::ZERO,
                OptionsError::HandshakeTimeout,
            ),
            (
                "endless handshake timeout",
                |o| o.handshake_timeout = Duration::MAX,
                OptionsError::HandshakeTimeout,
            ),
            (
                "zero hello timeout",
                |o| o.hello_timeout = Duration::ZERO,
                OptionsError::HelloTimeout,
            ),
            (
                "endless hello timeout",
                |o| o.hello_timeout = Duration::MAX,
                OptionsError::HelloTimeout,
            ),
            (
                "zero open timeout",
                |o| o.open_timeout = Duration::ZERO,
                OptionsError::OpenTimeout,
            ),
            (
                "endless open timeout",
                |o| o.open_timeout = Duration::MAX,
                OptionsError::OpenTimeout,
            ),
            (
                "endless close grace",
                |o| o.close_grace = Duration::MAX,
                OptionsError::CloseGrace,
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut options = TunnelOptions::default();
            mutate(&mut options);
            assert_eq!(options.validate(), Err(expected), "{name}");
        }
        let mut options = TunnelOptions::default();
        options.keepalive.interval = day_and_a_second;
        assert_eq!(options.validate(), Err(OptionsError::KeepaliveInterval));
    }

    #[test]
    fn boundary_values_are_accepted() {
        let options = TunnelOptions {
            max_concurrent_streams: 1,
            stream_window: 1,
            connection_window: MAX_WINDOW,
            max_header_list_size: MIN_HEADER_LIST_SIZE,
            keepalive: Keepalive {
                interval: Duration::from_nanos(1),
                timeout: MAX_TIMER,
            },
            close_grace: Duration::ZERO,
            ..TunnelOptions::default()
        };
        assert_eq!(options.validate(), Ok(()));
    }

    #[test]
    fn the_default_connection_window_leaves_room_for_sixteen_stalled_streams() {
        assert_eq!(DEFAULT_CONNECTION_WINDOW / DEFAULT_STREAM_WINDOW, 16);
    }
}
