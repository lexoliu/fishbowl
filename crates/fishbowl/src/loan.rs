//! Lending the researcher's agent login to a session for as long as it is open.
//!
//! The agents that run inside the session need a credential there. What Claude Code is
//! given is an access token and nothing else: the refresh token beside it in the
//! researcher's keychain is what their own Claude Code renews its login with, and
//! renewing rotates it, so a session that spent it would log them out of their own
//! machine. The token that does cross expires on its own within hours. Devin has no such
//! expiry to lean on: its credentials file is lent whole, so the loan ends not with a
//! clock but with the courier taking the file back when the agent exits.
//!
//! Either crosses over a unix socket the host owns, published inside the session by ssh
//! as a remote forward, and is answered one credential per connection. That shape is
//! deliberate: nothing is written down on the host, the session cannot reach the socket
//! after the ssh connection ends, and the courier can come back for a fresh credential
//! when the one it holds is nearly out — which is how a session outlives a single
//! token's lifetime, or a host-side re-login, without ever being handed what renews it.

use std::{
    io::ErrorKind,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use fishbowl_agents::{ClaudeLogin, DevinLogin};
use fishbowl_creds::{Bearer, Lent};
use jiff::{Timestamp, ToSpan as _};
use tokio::net::{UnixListener, UnixStream};

use crate::session::SessionId;

/// Longest path a unix socket may be bound at on macOS, including its terminator.
///
/// Binding past it fails with a message about an invalid argument that says nothing about
/// the length, so the length is checked here instead — where the answer is that the
/// researcher's home directory is deeper than this design allows for.
const MAX_SOCKET_PATH: usize = 104;

/// One opening of a session, named so that two of them cannot collide.
///
/// A researcher may have the same machine open twice — a shell in one window and Claude
/// Code in another, or two agents at once — and each opening publishes a socket and lands
/// a credential file inside the session. Naming both after the opening rather than after
/// the session is what keeps the second one from binding over the first one's socket and
/// overwriting the first one's credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    session: SessionId,
    nonce: String,
}

/// How many hexadecimal digits distinguish two openings of one session.
const NONCE_DIGITS: usize = 8;

/// How long before its expiry a token already in hand stops being handed out again.
///
/// Three times the courier's renewal period, so that a session asking on schedule is
/// never given a token with less than two renewals of life left, and the keychain is
/// read again in time to pick up the login the researcher's own Claude Code has renewed.
const REREAD_MARGIN_MINUTES: i64 = 15;

impl Attachment {
    /// Names a new opening of `session`.
    ///
    /// # Errors
    /// Fails when the operating system will not supply randomness, which is the one case
    /// where making up a name would risk landing on another opening's socket.
    pub fn random(session: SessionId) -> Result<Self> {
        let mut bytes = [0u8; NONCE_DIGITS / 2];
        getrandom::fill(&mut bytes).context("naming this opening of the session")?;
        let nonce = bytes.iter().fold(String::new(), |mut nonce, byte| {
            use std::fmt::Write as _;
            write!(nonce, "{byte:02x}").expect("a String never fails to be written to");
            nonce
        });
        Ok(Self { session, nonce })
    }

    /// File name of the socket the token is fetched over, on either machine.
    #[must_use]
    pub fn socket_name(&self) -> String {
        format!("{}-{}.sock", self.session, self.nonce)
    }

    /// File name of the credential the courier writes inside the session.
    #[must_use]
    pub fn credentials_name(&self) -> String {
        format!("{}-{}.json", self.session, self.nonce)
    }
}

/// Where the credential lent over a socket comes from.
///
/// Each arm is one agent's host-side login: what is lent, and how often it is re-read,
/// is that agent's business. Claude's token is remembered between asks because re-reading
/// the keychain is a question the operating system may put to the researcher; Devin's
/// file is re-read every ask because reading it is silent and a re-login on the host
/// should reach the session at the next renewal.
#[derive(Debug)]
pub enum Lender {
    /// The Claude Code keychain entry, lent as its access token.
    Claude(ClaudeLogin),
    /// The Devin credentials file, lent whole.
    Devin(DevinLogin),
}

/// A socket handing out the researcher's credential, and the task serving it.
#[derive(Debug)]
pub struct Loan {
    socket: PathBuf,
    server: tokio::task::JoinHandle<()>,
}

impl Loan {
    /// Starts lending from `lender` on a socket at `socket`.
    ///
    /// # Errors
    /// Fails when the socket path is longer than one can be bound at, or when it cannot
    /// be bound.
    pub async fn open(lender: Lender, socket: PathBuf) -> Result<Self> {
        if socket.as_os_str().len() >= MAX_SOCKET_PATH {
            bail!(
                "{} is too long to bind a socket at ({} bytes, and the limit is {})",
                socket.display(),
                socket.as_os_str().len(),
                MAX_SOCKET_PATH - 1
            );
        }
        prepare(&socket).await?;
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("listening on {}", socket.display()))?;

        Ok(Self {
            socket,
            server: tokio::spawn(serve(lender, listener)),
        })
    }

    /// The socket the session is to fetch from.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Stops lending and takes the socket back off the host's disk.
    ///
    /// # Errors
    /// Fails when the socket file exists but cannot be removed, which would leave the
    /// next attachment unable to bind its own.
    pub async fn close(self) -> Result<()> {
        self.server.abort();
        match tokio::fs::remove_file(&self.socket).await {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
            Err(source) => {
                Err(source).with_context(|| format!("removing {}", self.socket.display()))
            }
        }
    }
}

/// Makes the socket's directory, reachable by nobody else, and clears anything at the
/// path itself.
///
/// A socket file outlives the process that bound it, so one left behind by an attachment
/// that was killed rather than closed would otherwise make the next one fail to bind. The
/// name carries fresh randomness, so what is being cleared here is never a live socket.
async fn prepare(socket: &Path) -> Result<()> {
    if let Some(parent) = socket.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
        tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| format!("restricting {}", parent.display()))?;
    }
    match tokio::fs::remove_file(socket).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source).with_context(|| format!("clearing {}", socket.display())),
    }
}

/// Answers every connection with a credential, read from the login when the one in hand
/// is gone or about to go.
///
/// A Claude token is remembered rather than read every time, because a keychain read is a
/// question the operating system may put to the researcher — and the session asks every
/// few minutes. A token in hand is good until it expires whatever the researcher's own
/// Claude Code renews meanwhile, so nothing is lost by keeping it; it is read again as
/// expiry nears, which is when the renewed login is the one that matters. A token without
/// a stated expiry is kept for the run.
///
/// A connection that fails is logged and dropped. The session is untrusted, so a client
/// that hangs up mid-sentence is an ordinary event, and it must not end the lending for
/// the connection that comes after it.
async fn serve(lender: Lender, listener: UnixListener) {
    let mut in_hand = None;
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                if let Err(error) = lend(&lender, &mut in_hand, stream).await {
                    tracing::warn!("could not lend the login to the session: {error:#}");
                }
            }
            Err(error) => {
                tracing::warn!("the session's credential socket failed: {error}");
                return;
            }
        }
    }
}

/// Writes the credential a session may have over the connection.
///
/// For Claude that is the bearer from last time while it is still good for a while. For
/// Devin it is the credentials file read fresh: the file holds no expiry to schedule a
/// re-read by, and the read costs no prompt, so every ask gets whatever the host's Devin
/// is currently logged in as.
async fn lend(lender: &Lender, in_hand: &mut Option<Bearer>, stream: UnixStream) -> Result<()> {
    let lent = match lender {
        Lender::Claude(login) => {
            let bearer = match in_hand
                .take()
                .filter(|bearer| is_still_good(bearer, Timestamp::now()))
            {
                Some(bearer) => bearer,
                None => login.bearer().await.context("reading the login to lend")?,
            };
            *in_hand = Some(bearer.clone());
            Lent::Bearer(bearer)
        }
        Lender::Devin(login) => Lent::Document(
            login
                .document()
                .await
                .context("reading the login to lend")?,
        ),
    };
    lent.send(stream)
        .await
        .context("handing the credential to the session")
}

/// Whether `bearer` can be handed out at `now` without going back to the keychain.
fn is_still_good(bearer: &Bearer, now: Timestamp) -> bool {
    bearer
        .expires_at
        .is_none_or(|expiry| expiry > now + REREAD_MARGIN_MINUTES.minutes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn a_token_in_hand_is_reused_until_its_expiry_comes_within_the_margin() {
        let now = Timestamp::now();
        let bearer = |minutes_left: i64| Bearer {
            token: "sk-ant-oat01-x".to_owned(),
            expires_at: Some(now + minutes_left.minutes()),
        };
        assert!(is_still_good(&bearer(60), now));
        assert!(
            !is_still_good(&bearer(REREAD_MARGIN_MINUTES), now),
            "a session renewing on schedule must never be handed a token with less than \
             two renewals of life left"
        );
        assert!(!is_still_good(&bearer(-1), now));
        assert!(
            is_still_good(
                &Bearer {
                    token: "sk-ant-oat01-x".to_owned(),
                    expires_at: None,
                },
                now
            ),
            "an issuer that did not say when is not a reason to ask the researcher again"
        );
    }

    #[test]
    fn two_openings_of_one_session_do_not_land_on_each_others_files() {
        let session: SessionId = "c0ffee".parse().unwrap();
        let first = Attachment::random(session.clone()).unwrap();
        let second = Attachment::random(session).unwrap();

        assert_ne!(
            first.socket_name(),
            second.socket_name(),
            "a shell and an agent open at once are two openings of one machine, and the \
             second binding over the first one's socket would take its credential away"
        );
        assert!(first.socket_name().starts_with("c0ffee-"));
        assert_ne!(first.socket_name(), first.credentials_name());
    }

    #[tokio::test]
    async fn a_socket_path_the_operating_system_would_truncate_is_refused_before_binding() {
        let directory = TempDir::new().unwrap();
        let socket = directory.path().join("x".repeat(MAX_SOCKET_PATH));

        let refused = Loan::open(Lender::Claude(ClaudeLogin::discover()), socket)
            .await
            .unwrap_err();

        assert!(
            format!("{refused:#}").contains("too long"),
            "bind reports only an invalid argument, which says nothing about why: \
             {refused:#}"
        );
    }

    #[tokio::test]
    async fn the_directory_a_borrowed_token_is_served_from_is_the_researchers_alone() {
        let directory = TempDir::new().unwrap();
        let run = directory.path().join("run");
        prepare(&run.join("c0ffee.sock")).await.unwrap();

        let mode = tokio::fs::metadata(&run)
            .await
            .unwrap()
            .permissions()
            .mode();

        assert_eq!(
            mode & 0o777,
            0o700,
            "anyone who can connect to the socket is handed the researcher's token, so \
             the only account that may reach it is theirs"
        );
    }

    #[tokio::test]
    async fn a_socket_left_by_an_attachment_that_was_killed_does_not_block_the_next_one() {
        let directory = TempDir::new().unwrap();
        let socket = directory.path().join("c0ffee.sock");
        drop(UnixListener::bind(&socket).unwrap());
        assert!(socket.exists());

        prepare(&socket).await.unwrap();

        UnixListener::bind(&socket).expect("the stale socket has been cleared");
    }

    #[tokio::test]
    async fn one_connection_carries_one_token_and_then_ends() {
        let directory = TempDir::new().unwrap();
        let socket = directory.path().join("c0ffee.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let served = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            Lent::Bearer(Bearer {
                token: "sk-ant-oat01-borrowed".to_owned(),
                expires_at: None,
            })
            .send(stream)
            .await
            .unwrap();
        });

        let stream = UnixStream::connect(&socket).await.unwrap();
        let received = Lent::receive(stream).await.unwrap();

        served.await.unwrap();
        assert_eq!(
            received,
            Lent::Bearer(Bearer {
                token: "sk-ant-oat01-borrowed".to_owned(),
                expires_at: None,
            })
        );
    }
}
