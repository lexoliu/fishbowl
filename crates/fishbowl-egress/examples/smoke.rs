//! A live-fire check of the egress layer: registers a WARP device, raises the tunnel,
//! and proves a real connection crossed it — or refuses, in the strict modes.
//!
//! Run with a network, never in CI:
//!
//! ```sh
//! cargo run -p fishbowl-egress --example smoke --features warp,tor -- auto
//! ```

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use fishbowl_egress::{Egress, Mode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The resolver bootstrap traffic and DNS exchanges are pointed at.
const RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53);

/// Where transports keep what must persist between runs — a reused registration is the
/// polite thing against Cloudflare's rate limits.
fn state_dir() -> std::path::PathBuf {
    std::env::temp_dir().join("fishbowl-egress-smoke")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("fishbowl_egress=info")),
        )
        .init();

    let mode = match std::env::args().nth(1).as_deref() {
        None | Some("auto") => Mode::Auto,
        Some("warp") => Mode::Warp,
        Some("tor") => Mode::Tor,
        Some("direct") => Mode::Direct,
        Some(other) => panic!("unknown egress mode `{other}`"),
    };
    println!("mode: {mode}");

    let egress = Egress::start(mode, &state_dir(), RESOLVER);

    // Report route transitions as they happen — what the gateway's audit recorder does.
    let mut routes = egress.routes();
    let watcher = tokio::spawn(async move {
        loop {
            let (route, reason) = routes.current();
            match reason {
                Some(reason) => println!("route: {route} ({reason})"),
                None => println!("route: {route}"),
            }
            if routes.changed().await.is_none() {
                return;
            }
        }
    });

    // A DNS exchange: the wire message goes over whatever route connections take.
    let answer = egress.dns_exchange(RESOLVER, &example_com_query()).await;
    match answer {
        Ok(answer) => println!("dns: example.com answered in {}B", answer.len()),
        Err(error) => println!("dns: refused — {error}"),
    }

    // A TCP exchange: `cdn-cgi/trace` reports `warp=on` when Cloudflare sees the
    // connection come in through its own tunnel.
    match http_trace(&egress).await {
        Ok(response) => {
            let warp = response
                .lines()
                .find(|line| line.starts_with("warp="))
                .unwrap_or("warp=?");
            println!("http: {}", response.lines().next().unwrap_or("<empty>"));
            println!("http: {warp}");
        }
        Err(error) => println!("http: refused — {error}"),
    }

    watcher.abort();
    Ok(())
}

async fn http_trace(egress: &Egress) -> std::io::Result<String> {
    let mut stream = egress
        .connect(SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 80)))
        .await?;
    stream
        .write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

/// A wire-format A query for `example.com`, hand-built so the example builds without
/// either transport's dependencies.
fn example_com_query() -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer/authority/additional records
    ];
    for label in ["example", "com"] {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root, A, IN
    query
}
