//! The credential a session borrows, and the file it is borrowed through.
//!
//! Two agents are lent a login here, and the loan looks different for each. Claude Code
//! can be told that something other than itself holds its credential: given
//! [`MANAGED_BY_HOST`] it stops reading its own login and reads a file instead, and given
//! [`AUTH_ENV_VAR`] it takes the token out of the environment key it names. That is what
//! lets the copy of Claude Code inside a session be the researcher's own subscription
//! rather than an API key wearing its name — usage, subscription MCP servers, and the
//! rest arrive with it.
//!
//! What crosses into the session for Claude Code is [`Bearer`]: one access token and the
//! moment it stops working. The credential the host could mint more tokens with stays on
//! the host, so the worst a session can do with what it was lent is spend the few hours
//! it has. Devin has no such split: its login is a credentials file, and the file is lent
//! verbatim as a [`Lent::Document`] — which is why the courier taking it back when the
//! agent exits is the whole of what makes it a loan rather than a copy.
//!
//! Both ends of that loan are here because they are one agreement. The host writes
//! [`Lent`] into a session; the courier inside the session writes [`Credentials`] where
//! Claude Code reads it, or the document where Devin reads it. Nothing else may drift.

pub mod error;
pub mod file;
pub mod wire;

pub use error::CredentialError;
pub use file::{Credentials, MAX_BYTES, MODE, START_TOLERANCE, install, remove};
pub use wire::{Bearer, Lent};

use std::{collections::BTreeMap, path::Path};

/// Tells Claude Code its credential is held for it, and to stop looking for its own.
pub const MANAGED_BY_HOST: &str = "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST";

/// Names the file [`Credentials`] is read out of.
pub const CREDS_FILE: &str = "CLAUDE_CODE_HOST_CREDS_FILE";

/// Names the environment key the bearer token arrives under.
pub const AUTH_ENV_VAR: &str = "CLAUDE_CODE_HOST_AUTH_ENV_VAR";

/// The key we hand the token under.
///
/// Claude Code accepts several, and which one is chosen decides what the session is: as
/// `ANTHROPIC_AUTH_TOKEN` the same token authenticates a plain API client, while as an
/// OAuth token it authenticates the researcher's subscription, which is the point of
/// lending it at all.
pub const BEARER: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// Environment the credentials file carries, holding the token itself.
///
/// Only the bearer key is in it. Claude Code re-applies this environment every time it
/// re-reads the file, and refuses a re-read that changes which endpoint it is talking to,
/// so a loan that carried anything else would be a loan that could redirect the session.
#[must_use]
pub fn bearer_environment(token: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(BEARER.to_owned(), token.to_owned())])
}

/// Environment that puts Claude Code into host-managed mode against `creds_file`.
#[must_use]
pub fn launch_environment(creds_file: &Path) -> BTreeMap<String, String> {
    BTreeMap::from([
        (MANAGED_BY_HOST.to_owned(), "1".to_owned()),
        (CREDS_FILE.to_owned(), creds_file.display().to_string()),
        (AUTH_ENV_VAR.to_owned(), BEARER.to_owned()),
    ])
}
