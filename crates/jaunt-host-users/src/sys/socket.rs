use std::io::{self, Read};
use std::os::fd::BorrowedFd;
use std::time::Duration;

use rustix::io::Errno;
use rustix::net::sockopt::{Timeout, set_socket_timeout};

use crate::clock::Clock;

pub(crate) const SOCKET_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(target_os = "linux")]
pub(crate) fn peer_uid(socket: BorrowedFd<'_>) -> io::Result<u32> {
    Ok(rustix::net::sockopt::socket_peercred(socket)?.uid.as_raw())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn peer_uid(_socket: BorrowedFd<'_>) -> io::Result<u32> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub(crate) fn limit_waits(input: BorrowedFd<'_>, output: BorrowedFd<'_>) -> io::Result<()> {
    set_socket_timeout(input, Timeout::Recv, Some(SOCKET_TIMEOUT))?;
    set_socket_timeout(output, Timeout::Send, Some(SOCKET_TIMEOUT))?;
    Ok(())
}

pub(crate) struct ByteReader<'a> {
    socket: BorrowedFd<'a>,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(socket: BorrowedFd<'a>) -> Self {
        Self { socket }
    }
}

impl Read for ByteReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(byte) = buffer.get_mut(..1) else {
            return Ok(0);
        };
        Ok(rustix::io::read(self.socket, byte)?)
    }
}

pub(crate) fn send<C: Clock + ?Sized>(
    socket: BorrowedFd<'_>,
    mut bytes: &[u8],
    clock: &C,
    budget: Duration,
) -> io::Result<()> {
    let started = clock.now();
    while !bytes.is_empty() {
        match rustix::io::write(socket, bytes) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = bytes.get(written..).unwrap_or_default(),
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) if clock.now().saturating_duration_since(started) < budget => {}
            Err(errno) => return Err(errno.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    use super::{ByteReader, limit_waits, send};
    use crate::line::{LineError, MAX_REQUEST_BYTES, read_line};
    use crate::sys::SystemClock;
    use crate::testing::within;

    #[test]
    fn the_request_line_is_read_without_consuming_a_byte_past_the_newline() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(b"{\"v\":1}\nrest").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let line = read_line(
            &mut ByteReader::new(server.as_fd()),
            &SystemClock,
            Duration::from_secs(5),
            MAX_REQUEST_BYTES,
        )
        .unwrap();
        assert_eq!(line, b"{\"v\":1}");
        let mut rest = Vec::new();
        (&server).read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"rest");
    }

    #[test]
    fn a_silent_peer_runs_out_the_budget_because_reads_wake_up() {
        let (_client, server) = UnixStream::pair().unwrap();
        limit_waits(server.as_fd(), server.as_fd()).unwrap();
        let started = Instant::now();
        let error = within("reading from a silent peer", move || {
            read_line(
                &mut ByteReader::new(server.as_fd()),
                &SystemClock,
                Duration::from_millis(1500),
                MAX_REQUEST_BYTES,
            )
        })
        .unwrap_err();
        assert!(matches!(error, LineError::TimedOut { .. }), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_response_is_written_whole() {
        let (mut client, server) = UnixStream::pair().unwrap();
        send(
            server.as_fd(),
            b"{\"v\":1,\"result\":\"exists\"}\n",
            &SystemClock,
            Duration::from_secs(3),
        )
        .unwrap();
        drop(server);
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"{\"v\":1,\"result\":\"exists\"}\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_peer_uid_comes_from_the_kernel_and_a_non_socket_is_an_error() {
        let (_client, server) = UnixStream::pair().unwrap();
        assert_eq!(
            super::peer_uid(server.as_fd()).unwrap(),
            rustix::process::getuid().as_raw()
        );
        let file = tempfile::tempfile().unwrap();
        assert!(super::peer_uid(file.as_fd()).is_err());
    }
}
