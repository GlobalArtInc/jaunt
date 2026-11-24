use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLIENT_PREFACE_LEN: usize = 24;
const FRAME_HEADER_LEN: usize = 9;
const GOAWAY: u8 = 7;

pub struct FrameTap<IO> {
    inner: IO,
    preface_left: usize,
    header: Vec<u8>,
    payload_left: usize,
    payload: Option<Vec<u8>>,
    goaway_codes: Arc<Mutex<Vec<u32>>>,
}

impl<IO> FrameTap<IO> {
    pub fn new(inner: IO) -> (Self, Arc<Mutex<Vec<u32>>>) {
        let goaway_codes = Arc::new(Mutex::new(Vec::new()));
        let tap = Self {
            inner,
            preface_left: CLIENT_PREFACE_LEN,
            header: Vec::new(),
            payload_left: 0,
            payload: None,
            goaway_codes: goaway_codes.clone(),
        };
        (tap, goaway_codes)
    }

    fn feed(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.preface_left > 0 {
                let skip = bytes.len().min(self.preface_left);
                self.preface_left -= skip;
                bytes = &bytes[skip..];
            } else if self.payload_left > 0 {
                let take = bytes.len().min(self.payload_left);
                if let Some(payload) = &mut self.payload {
                    payload.extend_from_slice(&bytes[..take]);
                }
                self.payload_left -= take;
                bytes = &bytes[take..];
                if self.payload_left == 0 {
                    self.finish_frame();
                }
            } else {
                let take = bytes.len().min(FRAME_HEADER_LEN - self.header.len());
                self.header.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                if self.header.len() == FRAME_HEADER_LEN {
                    self.payload_left = (usize::from(self.header[0]) << 16)
                        | (usize::from(self.header[1]) << 8)
                        | usize::from(self.header[2]);
                    self.payload = (self.header[3] == GOAWAY).then(Vec::new);
                    self.header.clear();
                    if self.payload_left == 0 {
                        self.finish_frame();
                    }
                }
            }
        }
    }

    fn finish_frame(&mut self) {
        if let Some(payload) = self.payload.take()
            && payload.len() >= 8
        {
            let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            self.goaway_codes.lock().unwrap().push(code);
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for FrameTap<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) {
            let fresh = buf.filled()[before..].to_vec();
            self.feed(&fresh);
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for FrameTap<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
