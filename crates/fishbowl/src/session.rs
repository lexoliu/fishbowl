use std::{
    fmt::{self, Write as _},
    net::Ipv4Addr,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use anyhow::{Context as _, Result};
use fishbowl_agents::SandboxEndpoint;
use fishbowl_runtime::{Arch, ContainerName, ImageReference};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// How many hexadecimal digits a session identifier is written with.
///
/// Short enough to type into `fishbowl audit <session>` from memory, and wide enough
/// that the handful of sessions a host ever holds at once do not collide — and a
/// collision is caught anyway, because a new identifier is only accepted when neither the
/// host's state nor the runtime already holds it.
const DIGITS: usize = 6;

/// The name of one research environment.
///
/// A session identifier is also the runtime's container name, the SSH identity's file
/// name and the agents' entry id, so it is constrained to what the narrowest of those
/// accepts: lowercase hexadecimal, and nothing else. Nothing derived from the user is
/// ever spliced into a container name or a path this way.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(String);

impl SessionId {
    /// Draws an identifier from the operating system's entropy source.
    ///
    /// # Errors
    /// Fails when the operating system will not supply randomness, which is the one case
    /// where making up an identifier would risk reusing another session's machine.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; DIGITS.div_ceil(2)];
        getrandom::fill(&mut bytes).context("drawing a session identifier from the system")?;
        let mut id = String::with_capacity(DIGITS);
        for byte in bytes {
            write!(id, "{byte:02x}").expect("a String never fails to be written to");
        }
        id.truncate(DIGITS);
        Ok(Self(id))
    }

    /// The identifier as it is typed and stored.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The runtime's name for this session's machine.
    ///
    /// # Errors
    /// Fails only if the runtime's naming rules stop accepting hexadecimal.
    pub fn container_name(&self) -> Result<ContainerName> {
        ContainerName::new(self.0.clone()).map_err(Into::into)
    }
}

/// A string that is not a session identifier this tool ever issued.
#[derive(Debug, thiserror::Error)]
#[error(
    "`{0}` is not a session; a session is {DIGITS} hexadecimal digits, as printed when it \
     was created"
)]
pub struct NotASession(String);

impl FromStr for SessionId {
    type Err = NotASession;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == DIGITS && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(NotASession(value.to_owned()))
        }
    }
}

impl TryFrom<String> for SessionId {
    type Error = NotASession;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<SessionId> for String {
    fn from(id: SessionId) -> Self {
        id.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.pad(&self.0)
    }
}

/// What the host remembers about one session between invocations.
///
/// The runtime is the authority on whether a session's machine is running; this record
/// holds the facts the runtime does not keep, above all which host key reaches the machine
/// and which host directory its samples came from.
///
/// The machine's address is deliberately not among them. One is assigned when it starts
/// and a different one the next time, so an address written here would be a fact with an
/// expiry date: every consumer asks the runtime for it instead, which is why
/// [`Self::endpoint`] cannot be built without one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Identifier, which is also the container name and the agents' entry id.
    pub id: SessionId,
    /// Image the session's machine was created from.
    pub image: ImageReference,
    /// Guest architecture.
    pub arch: Arch,
    /// Port sshd listens on inside the machine.
    pub ssh_port: u16,
    /// Account the session logs in as.
    pub researcher: String,
    /// Directory the session starts in inside the machine.
    pub work_dir: PathBuf,
    /// Host directory mounted read-only as the sample source, when one was given.
    pub samples: Option<PathBuf>,
    /// Private key the host authenticates with.
    pub identity_file: PathBuf,
    /// When the session was created.
    pub created_at: Timestamp,
    /// When the session was last opened.
    ///
    /// This is what decides which sessions are reclaimed: the least recently opened go
    /// first, and one untouched for long enough goes whether the host is short of room or
    /// not.
    pub last_used: Timestamp,
}

impl SessionRecord {
    /// How long ago the session was last opened.
    ///
    /// A record written by a host whose clock has since been set back reads as brand new
    /// rather than as an error, because an unreadable age must never be a reason to
    /// reclaim someone's environment.
    #[must_use]
    pub fn idle_for(&self, now: Timestamp) -> Duration {
        now.duration_since(self.last_used)
            .try_into()
            .unwrap_or(Duration::ZERO)
    }

    /// The endpoint this session is reached at.
    ///
    /// Takes the address rather than holding one: requiring the caller to have just asked
    /// the runtime is what stops a stale address from being dialled.
    ///
    /// `known_hosts` is passed for the same reason the address is: it is derived from the
    /// host's state directory, which the record does not know about. `send_environment`
    /// is what the host has of the researcher's own keys right now, which no record can
    /// know either.
    #[must_use]
    pub fn endpoint(
        &self,
        address: Ipv4Addr,
        known_hosts: PathBuf,
        send_environment: Vec<String>,
    ) -> SandboxEndpoint {
        SandboxEndpoint {
            id: self.id.to_string(),
            user: self.researcher.clone(),
            host: address.to_string(),
            port: self.ssh_port,
            identity_file: self.identity_file.clone(),
            known_hosts,
            start_directory: self.work_dir.clone(),
            send_environment,
        }
    }
}

/// How an age is written in the session picker: the largest unit that still says
/// something, because "3d" is what a person compares and "281431s" is not.
#[must_use]
pub fn describe_age(age: Duration) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    let seconds = age.as_secs();
    match seconds {
        0..MINUTE => "just now".to_owned(),
        MINUTE..HOUR => format!("{}m ago", seconds / MINUTE),
        HOUR..DAY => format!("{}h ago", seconds / HOUR),
        _ => format!("{}d ago", seconds / DAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identifier_is_hexadecimal_and_nothing_else() {
        assert!("a3f19c".parse::<SessionId>().is_ok());
        assert!(
            "a3f19".parse::<SessionId>().is_err(),
            "a short identifier is a typo, not a prefix to guess from"
        );
        assert!(
            "../../etc".parse::<SessionId>().is_err(),
            "the identifier becomes a container name and a file name, so anything that \
             could traverse either is refused before it is used"
        );
    }

    #[test]
    fn a_drawn_identifier_is_one_the_runtime_accepts() {
        let id = SessionId::random().unwrap();
        assert_eq!(id.as_str().len(), DIGITS);
        id.container_name()
            .expect("a drawn identifier is always a valid container name");
    }

    #[test]
    fn an_age_is_written_in_the_largest_unit_that_still_says_something() {
        assert_eq!(describe_age(Duration::from_secs(30)), "just now");
        assert_eq!(describe_age(Duration::from_secs(3 * 60)), "3m ago");
        assert_eq!(describe_age(Duration::from_secs(5 * 3600)), "5h ago");
        assert_eq!(describe_age(Duration::from_secs(9 * 86400)), "9d ago");
    }

    #[test]
    fn a_clock_set_backwards_makes_a_session_look_new_rather_than_stale() {
        let record = SessionRecord {
            id: "a3f19c".parse().unwrap(),
            image: ImageReference::new("localhost/fishbowl:arm64").unwrap(),
            arch: Arch::Arm64,
            ssh_port: 22,
            researcher: "researcher".to_owned(),
            work_dir: PathBuf::from("/work"),
            samples: None,
            identity_file: PathBuf::from("/keys/a3f19c"),
            created_at: Timestamp::now(),
            last_used: Timestamp::now(),
        };
        let earlier = record.last_used - jiff::SignedDuration::from_hours(1);
        assert_eq!(
            record.idle_for(earlier),
            Duration::ZERO,
            "an environment must never be reclaimed because the host's clock moved"
        );
    }
}
