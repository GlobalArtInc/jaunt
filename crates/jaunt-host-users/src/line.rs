use std::io::{self, Read};
use std::time::Duration;

use crate::clock::Clock;

pub const MAX_REQUEST_BYTES: usize = 1024;
pub const MAX_RESPONSE_BYTES: usize = 4096;
pub const REQUEST_BUDGET: Duration = Duration::from_secs(5);

const CHUNK_BYTES: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum LineError {
    #[error("the line is longer than {limit} bytes")]
    TooLong { limit: usize },
    #[error("the connection ended before the end of the line")]
    Unterminated,
    #[error("the line did not arrive within {budget:?}")]
    TimedOut { budget: Duration },
    #[error("the reader returned more bytes than it was given room for")]
    Overrun,
    #[error("reading the line failed: {0}")]
    Io(#[source] io::Error),
}

pub fn read_line<R, C>(
    reader: &mut R,
    clock: &C,
    budget: Duration,
    limit: usize,
) -> Result<Vec<u8>, LineError>
where
    R: Read + ?Sized,
    C: Clock + ?Sized,
{
    let started = clock.now();
    let check_budget = || {
        if clock.now().saturating_duration_since(started) >= budget {
            Err(LineError::TimedOut { budget })
        } else {
            Ok(())
        }
    };
    let mut line = Vec::new();
    let mut chunk = [0_u8; CHUNK_BYTES];
    loop {
        check_budget()?;
        let room = limit
            .saturating_add(1)
            .saturating_sub(line.len())
            .min(CHUNK_BYTES);
        let buffer = chunk.get_mut(..room).ok_or(LineError::Overrun)?;
        let read = match reader.read(buffer) {
            Ok(0) => return Err(LineError::Unterminated),
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(LineError::Io(error)),
        };
        let received = chunk
            .get(..read)
            .filter(|_| read <= room)
            .ok_or(LineError::Overrun)?;
        check_budget()?;
        let (piece, finished) = match received.iter().position(|byte| *byte == b'\n') {
            Some(end) => (received.get(..end).unwrap_or_default(), true),
            None => (received, false),
        };
        line.extend_from_slice(piece);
        if line.len() > limit {
            return Err(LineError::TooLong { limit });
        }
        if finished {
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Read};
    use std::time::Duration;

    use super::{LineError, MAX_REQUEST_BYTES, REQUEST_BUDGET, read_line};
    use crate::testing::FakeClock;

    enum Step {
        Data(Vec<u8>),
        Fail(io::ErrorKind),
    }

    struct Scripted<'a> {
        steps: VecDeque<Step>,
        clock: &'a FakeClock,
        per_read: Duration,
    }

    impl<'a> Scripted<'a> {
        fn new(clock: &'a FakeClock, per_read: Duration, steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
                clock,
                per_read,
            }
        }
    }

    impl Read for Scripted<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.clock.advance(self.per_read);
            match self.steps.pop_front() {
                None => Ok(0),
                Some(Step::Fail(kind)) => Err(io::Error::from(kind)),
                Some(Step::Data(mut data)) => {
                    let taken = data.len().min(buffer.len());
                    buffer[..taken].copy_from_slice(&data[..taken]);
                    if taken < data.len() {
                        self.steps.push_front(Step::Data(data.split_off(taken)));
                    }
                    Ok(taken)
                }
            }
        }
    }

    fn read_all(bytes: &[u8]) -> Result<Vec<u8>, LineError> {
        let clock = FakeClock::started();
        let mut reader = Scripted::new(&clock, Duration::ZERO, vec![Step::Data(bytes.to_vec())]);
        read_line(&mut reader, &clock, REQUEST_BUDGET, MAX_REQUEST_BYTES)
    }

    #[test]
    fn a_line_of_exactly_the_limit_is_accepted_and_one_byte_more_is_refused() {
        let exact = [vec![b'a'; MAX_REQUEST_BYTES], b"\n".to_vec()].concat();
        assert_eq!(read_all(&exact).unwrap(), vec![b'a'; MAX_REQUEST_BYTES]);

        let over = [vec![b'a'; MAX_REQUEST_BYTES + 1], b"\n".to_vec()].concat();
        assert!(matches!(
            read_all(&over),
            Err(LineError::TooLong {
                limit: MAX_REQUEST_BYTES
            })
        ));

        let endless = vec![b'a'; MAX_REQUEST_BYTES * 4];
        assert!(matches!(read_all(&endless), Err(LineError::TooLong { .. })));
    }

    #[test]
    fn a_line_without_a_newline_is_unterminated() {
        assert!(matches!(
            read_all(b"{\"v\":1}"),
            Err(LineError::Unterminated)
        ));
        assert!(matches!(read_all(b""), Err(LineError::Unterminated)));
    }

    #[test]
    fn bytes_after_the_newline_are_left_alone() {
        assert_eq!(read_all(b"{}\nrest").unwrap(), b"{}");
        assert_eq!(read_all(b"\n").unwrap(), b"");
    }

    #[test]
    fn a_slow_reader_runs_out_of_the_budget() {
        let clock = FakeClock::started();
        let steps = b"{\"v\":1}\n"
            .iter()
            .map(|byte| Step::Data(vec![*byte]))
            .collect();
        let mut reader = Scripted::new(&clock, Duration::from_secs(1), steps);
        let error = read_line(&mut reader, &clock, REQUEST_BUDGET, MAX_REQUEST_BYTES).unwrap_err();
        assert!(matches!(error, LineError::TimedOut { .. }), "{error}");
        assert_eq!(clock.elapsed(), REQUEST_BUDGET);

        let clock = FakeClock::started();
        let steps = vec![
            Step::Data(b"{\"v\"".to_vec()),
            Step::Fail(io::ErrorKind::WouldBlock),
            Step::Fail(io::ErrorKind::WouldBlock),
            Step::Data(b":1}\n".to_vec()),
        ];
        let mut reader = Scripted::new(&clock, Duration::from_secs(2), steps);
        let error = read_line(&mut reader, &clock, REQUEST_BUDGET, MAX_REQUEST_BYTES).unwrap_err();
        assert!(matches!(error, LineError::TimedOut { .. }), "{error}");
    }

    #[test]
    fn interruptions_and_timeouts_within_the_budget_are_retried_and_other_errors_end_the_read() {
        let clock = FakeClock::started();
        let steps = vec![
            Step::Data(b"{\"v\"".to_vec()),
            Step::Fail(io::ErrorKind::Interrupted),
            Step::Fail(io::ErrorKind::WouldBlock),
            Step::Fail(io::ErrorKind::TimedOut),
            Step::Data(b":1}\n".to_vec()),
        ];
        let mut reader = Scripted::new(&clock, Duration::from_millis(900), steps);
        let line = read_line(&mut reader, &clock, REQUEST_BUDGET, MAX_REQUEST_BYTES).unwrap();
        assert_eq!(line, b"{\"v\":1}");

        let clock = FakeClock::started();
        let steps = vec![Step::Fail(io::ErrorKind::ConnectionReset)];
        let mut reader = Scripted::new(&clock, Duration::ZERO, steps);
        let error = read_line(&mut reader, &clock, REQUEST_BUDGET, MAX_REQUEST_BYTES).unwrap_err();
        assert!(matches!(error, LineError::Io(_)), "{error}");
    }
}
