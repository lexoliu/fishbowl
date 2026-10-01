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
        Some("redteam") => Mode::Redteam,
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
    let answer = egress.dns_exchange(RESOLVER, &a_query("example.com")).await;
    match answer {
        Ok(answer) => println!("dns: example.com answered in {}B", answer.len()),
        Err(error) => println!("dns: refused — {error}"),
    }

    // A TCP exchange: `cdn-cgi/trace` reports `warp=on` when Cloudflare sees the
    // connection come in through its own tunnel. Over Tor the probe goes elsewhere —
    // Cloudflare's edge drops Tor exits outright.
    let target = match mode {
        // `redteam` prefers Tor — probe somewhere an exit can reach; if it fell back
        // to WARP the same probe still answers.
        Mode::Tor | Mode::Redteam => ("detectportal.firefox.com", "/"),
        _ => ("www.cloudflare.com", "/cdn-cgi/trace"),
    };
    match http_trace(&egress, target).await {
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

async fn http_trace(egress: &Egress, (host, path): (&str, &str)) -> std::io::Result<String> {
    // `1.1.1.1` now redirects the trace to HTTPS; `www.cloudflare.com` still answers it
    // on port 80. Resolving it through the egress keeps the lookup on the tunnel too.
    // Over Tor a stream can be accepted by an exit and still die at first use, so the
    // exchange retries a few times like the transport's own exchanges do.
    let mut last_error = None;
    for _ in 0..4 {
        match http_exchange(egress, (host, path)).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| std::io::Error::other("no exchange could land")))
}

async fn http_exchange(egress: &Egress, (host, path): (&str, &str)) -> std::io::Result<String> {
    let answer = egress.dns_exchange(RESOLVER, &a_query(host)).await?;
    let address = first_a(&answer)
        .ok_or_else(|| std::io::Error::other(format!("{host} carried no A record")))?;
    let mut stream = egress.connect(SocketAddr::from((address, 80))).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

/// A wire-format A query for `name`, hand-built so the example builds without either
/// transport's dependencies.
fn a_query(name: &str) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, // id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // no answer/authority/additional records
    ];
    for label in name.split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]); // root, A, IN
    query
}

/// The first A record in a wire-format DNS response, walked by hand for the same reason
/// the query is.
fn first_a(message: &[u8]) -> Option<Ipv4Addr> {
    let header = message.get(..12)?;
    let questions = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let answers = usize::from(u16::from_be_bytes([header[6], header[7]]));
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)? + 4;
    }
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        let fields = message.get(offset..offset + 10)?;
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        let length = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        offset += 10;
        let rdata = message.get(offset..offset + length)?;
        if record_type == 1 && length == 4 {
            return Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        offset += length;
    }
    None
}

/// Where a DNS name ends: at the root label or at a compression pointer.
fn skip_name(message: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let byte = *message.get(offset)?;
        if byte == 0 {
            return Some(offset + 1);
        }
        if byte & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        offset += 1 + usize::from(byte);
    }
}
