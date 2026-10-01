//! Reading a TLS client hello without answering it.
//!
//! The `default` audit tier never terminates TLS, but a session's trail still wants the
//! one thing the hello says out loud: where the client thinks it is going. The bytes
//! are read into the connection's prefix buffer, pushed through rustls' own parser,
//! and replayed to the upstream untouched — whether they parse or not, the relay is
//! the same, so an unparseable hello costs a record's metadata and never the
//! connection.

use std::time::Duration;

use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::stream::Prefixed;

/// How long the sandbox may take to finish its hello before the metadata is given up
/// on — the connection is relayed either way.
const HELLO_DEADLINE: Duration = Duration::from_secs(2);

/// The most hello the sniffer buffers. A real client hello is a few hundred bytes; the
/// bound exists for clients that send garbage that happens to start with `0x16 0x03`.
const HELLO_CAP: usize = 128 * 1024;

/// What the client declared at the start of a TLS session.
#[derive(Debug, Default)]
pub struct ClientHelloMeta {
    /// Server name the client offered, when it offered one.
    pub server_name: Option<String>,
    /// ALPN protocols the client offered.
    pub alpn: Vec<String>,
}

/// Reads the client hello inside `probed` and reports what it declared.
///
/// The returned stream is the same connection with every byte preserved for replay —
/// including hellos that could not be parsed, which are relayed like any other bytes.
///
/// # Errors
/// Fails when the connection itself fails while the hello is being read.
pub async fn observe<S>(mut probed: Prefixed<S>) -> io::Result<(Prefixed<S>, ClientHelloMeta)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // An Acceptor carries a whole connection state (~18 KiB); boxing keeps this
    // function's future small.
    let mut acceptor = Box::new(rustls::server::Acceptor::default());
    let deadline = tokio::time::sleep(HELLO_DEADLINE);
    tokio::pin!(deadline);
    // How much of the buffered prefix has already been fed to the acceptor — its
    // deframer consumes what it is given, so bytes must never be pushed twice.
    let mut fed = 0usize;
    let meta = loop {
        {
            // Push the newly buffered bytes only. A `&[u8]` reader ends on `Ok(0)`,
            // which is the signal to go read more of the connection.
            let mut fresh = &probed.prefix()[fed..];
            while acceptor.read_tls(&mut fresh)? > 0 {}
            fed = probed.prefix().len();
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => break declared(&accepted.client_hello()),
            Ok(None) => {}
            // A hello rustls will not parse still belongs upstream exactly as sent.
            Err(_) => break ClientHelloMeta::default(),
        }
        if probed.prefix().len() >= HELLO_CAP {
            break ClientHelloMeta::default();
        }
        tokio::select! {
            () = &mut deadline => break ClientHelloMeta::default(),
            read = probed.read_more() => match read {
                Ok(0) => break ClientHelloMeta::default(),
                Ok(_) => {}
                Err(error) => return Err(error),
            },
        }
    };
    Ok((probed, meta))
}

/// What the hello declared, reduced to what the audit trail records.
fn declared(hello: &rustls::server::ClientHello<'_>) -> ClientHelloMeta {
    ClientHelloMeta {
        server_name: hello.server_name().map(str::to_owned),
        alpn: hello
            .alpn()
            .map(|protocols| {
                protocols
                    .map(|protocol| String::from_utf8_lossy(protocol).into_owned())
                    .collect()
            })
            .unwrap_or_default(),
    }
}
