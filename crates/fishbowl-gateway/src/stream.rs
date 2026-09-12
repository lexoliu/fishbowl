//! Protocol probing without losing the bytes that were probed.
//!
//! The gateway has to decide what a connection is before it can audit it, and some
//! protocols expect the server to speak first. Reading a short prefix under a deadline and
//! handing it back to whichever handler wins is what lets both cases work.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Bytes read before deciding what protocol a connection carries.
pub const PROBE_LEN: usize = 8;

/// How long a silent client is given before the gateway treats it as server-speaks-first.
pub const PROBE_WAIT: Duration = Duration::from_millis(200);

/// A stream whose first bytes have already been read.
#[derive(Debug)]
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    position: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    /// The bytes that were consumed while probing.
    #[must_use]
    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }
}

impl<S: AsyncRead + Unpin> Prefixed<S> {
    /// Reads up to [`PROBE_LEN`] bytes, giving up after [`PROBE_WAIT`].
    ///
    /// A timeout is not a failure: a connection whose client says nothing is exactly the
    /// case this function exists to report.
    pub async fn probe(mut inner: S) -> io::Result<Self> {
        let mut prefix = vec![0_u8; PROBE_LEN];
        let mut filled = 0;
        let deadline = tokio::time::sleep(PROBE_WAIT);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                () = &mut deadline => break,
                read = inner.read(&mut prefix[filled..]) => match read? {
                    0 => break,
                    count => {
                        filled += count;
                        if filled == PROBE_LEN {
                            break;
                        }
                    }
                },
            }
        }
        prefix.truncate(filled);
        Ok(Self {
            prefix,
            position: 0,
            inner,
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.position < this.prefix.len() {
            let remaining = &this.prefix[this.position..];
            let taken = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..taken]);
            this.position += taken;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// Whether a probed prefix is the start of an HTTP/1.x request line.
#[must_use]
pub fn looks_like_http(prefix: &[u8]) -> bool {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|method| prefix.starts_with(method))
}

/// Whether a probed prefix is the start of a TLS handshake record.
#[must_use]
pub fn looks_like_tls(prefix: &[u8]) -> bool {
    matches!(prefix, [0x16, 0x03, ..])
}

#[cfg(test)]
mod tests {
    use super::{looks_like_http, looks_like_tls};

    #[test]
    fn a_client_hello_is_recognised_as_tls() {
        assert!(looks_like_tls(&[0x16, 0x03, 0x01, 0x02, 0x00]));
        assert!(!looks_like_tls(b"GET / HTTP"));
    }

    #[test]
    fn only_complete_method_tokens_count_as_http() {
        assert!(looks_like_http(b"GET /ind"));
        assert!(!looks_like_http(b"GETTY"));
        assert!(!looks_like_http(&[0x16, 0x03, 0x01]));
    }
}
