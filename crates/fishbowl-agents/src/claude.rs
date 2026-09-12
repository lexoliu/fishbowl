//! The researcher's own Claude Code login, read so a session can borrow from it.
//!
//! Claude Code keeps its login in the login keychain, under a service name it derives
//! from which configuration directory it was started with. Reading it is how a session
//! gets to be the researcher's own subscription rather than a second account: the copy of
//! Claude Code inside the sandbox is handed the same OAuth bearer the copy outside uses,
//! and so reports the same usage and sees the same subscription connectors.
//!
//! Only the access token is taken. The refresh token beside it is what the researcher's
//! own Claude Code renews its login with, and renewing rotates it — so a second process
//! spending it would log the researcher out of their own machine. This module never
//! writes the keychain, never refreshes, and never deserialises the refresh token at all.

use std::env;

use fishbowl_creds::Bearer;
use jiff::Timestamp;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;

use crate::error::AgentError;

/// Environment variable naming the directory Claude Code keeps its configuration in.
const CONFIG_DIR: &str = "CLAUDE_CONFIG_DIR";

/// Environment variable that overrides the above for stored secrets alone.
const SECURESTORAGE_CONFIG_DIR: &str = "CLAUDE_SECURESTORAGE_CONFIG_DIR";

/// Keychain service name for a Claude Code running out of its default directory.
const DEFAULT_SERVICE: &str = "Claude Code-credentials";

/// Account name Claude Code falls back to when the user's own is unusable as one.
const FALLBACK_ACCOUNT: &str = "claude-code-user";

/// Characters Claude Code accepts in the account name before falling back.
fn is_account_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}

/// The keychain entry holding the researcher's Claude Code login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeLogin {
    service: String,
    account: String,
}

impl ClaudeLogin {
    /// Works out which entry this machine's Claude Code would be using.
    ///
    /// A Claude Code pointed at a configuration directory of its own stores its login
    /// under a service name carrying a digest of that directory, so that two of them side
    /// by side are two logins. Following the same derivation is what lets a session
    /// borrow from whichever one the researcher actually runs.
    #[must_use]
    pub fn discover() -> Self {
        Self {
            service: service(),
            account: account(),
        }
    }

    /// Keychain service name being read.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Keychain account name being read.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Reads the login and answers with the part of it a session may borrow.
    ///
    /// # Errors
    /// Fails when there is no login to borrow from, when the keychain refuses, when what
    /// is stored is not what Claude Code writes, and when the token has already expired —
    /// which only the researcher's own Claude Code can put right, by being run once.
    pub async fn bearer(&self) -> Result<Bearer, AgentError> {
        let stored = self.read().await?;
        let bearer = stored.into_bearer(&self.service)?;
        match bearer.expires_at {
            Some(expiry) if expiry <= Timestamp::now() => Err(AgentError::LoginExpired {
                service: self.service.clone(),
                expired_at: expiry,
            }),
            _ => Ok(bearer),
        }
    }

    /// Fetches and parses the keychain entry.
    ///
    /// The read happens on a blocking thread because the keychain is entitled to stop and
    /// ask the researcher whether this program may have the secret, and a dialog box is
    /// not something an executor thread can wait on.
    async fn read(&self) -> Result<StoredLogin, AgentError> {
        let service = self.service.clone();
        let account = self.account.clone();
        let secret = tokio::task::spawn_blocking(move || {
            security_framework::passwords::get_generic_password(&service, &account)
        })
        .await
        .map_err(|source| AgentError::KeychainUnreachable {
            service: self.service.clone(),
            source,
        })?
        .map_err(|source| {
            if source.code() == ITEM_NOT_FOUND {
                AgentError::NoLogin {
                    service: self.service.clone(),
                }
            } else {
                AgentError::Keychain {
                    service: self.service.clone(),
                    source,
                }
            }
        })?;

        serde_json::from_slice(&secret).map_err(|source| AgentError::StoredLogin {
            service: self.service.clone(),
            source,
        })
    }
}

/// What the keychain answers with when nothing is stored under the name asked for.
const ITEM_NOT_FOUND: i32 = -25300;

/// The keychain entry, read for the one field a session is allowed to see.
///
/// `refreshToken` and `refreshTokenExpiresAt` are in the stored JSON and are deliberately
/// absent here. Serde ignores what it is not asked for, so the credential that could mint
/// further tokens is never even decoded, let alone carried anywhere.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredLogin {
    claude_ai_oauth: Option<StoredOauth>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredOauth {
    access_token: String,
    #[serde(default, with = "jiff::fmt::serde::timestamp::millisecond::optional")]
    expires_at: Option<Timestamp>,
}

impl StoredLogin {
    /// Takes the access token out, refusing a login that is not an OAuth one.
    fn into_bearer(self, service: &str) -> Result<Bearer, AgentError> {
        let oauth = self.claude_ai_oauth.ok_or_else(|| AgentError::NotOauth {
            service: service.to_owned(),
        })?;
        Ok(Bearer {
            token: oauth.access_token,
            expires_at: oauth.expires_at,
        })
    }
}

/// The keychain service name Claude Code would use on this machine.
fn service() -> String {
    let Some(directory) = distinct_config_dir() else {
        return DEFAULT_SERVICE.to_owned();
    };
    let digest = Sha256::digest(directory.as_bytes());
    format!(
        "{DEFAULT_SERVICE}-{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3]
    )
}

/// The configuration directory, when it is one that earns a service name of its own.
///
/// Claude Code treats the variables as unset when they are empty, and a login stored by
/// a default installation carries no digest — so the answer here is `None` far more often
/// than not.
fn distinct_config_dir() -> Option<String> {
    match env::var(SECURESTORAGE_CONFIG_DIR) {
        // Set at all means it decides, including deciding to be the default by being empty.
        Ok(directory) if directory.is_empty() => None,
        Ok(directory) => Some(normalised(&directory)),
        Err(_) => match env::var(CONFIG_DIR) {
            Ok(directory) if !directory.is_empty() => Some(normalised(&directory)),
            _ => None,
        },
    }
}

/// The path as Claude Code digests it.
///
/// macOS hands out decomposed paths in places Finder has been, so the same directory can
/// arrive spelled two ways; Claude Code composes before digesting and so must this.
fn normalised(directory: &str) -> String {
    directory.nfc().collect()
}

/// The keychain account name Claude Code would use on this machine.
fn account() -> String {
    let name = env::var("USER")
        .ok()
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_default();
    if name.is_empty() || !name.chars().all(is_account_character) {
        return FALLBACK_ACCOUNT.to_owned();
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_installation_is_read_under_the_plain_name() {
        assert_eq!(DEFAULT_SERVICE, "Claude Code-credentials");
    }

    #[test]
    fn only_the_access_token_is_taken_out_of_what_is_stored() {
        let stored: StoredLogin = serde_json::from_str(
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-borrowed",
                 "refreshToken":"sk-ant-ort01-must-never-leave",
                 "expiresAt":1788521737675,"refreshTokenExpiresAt":1790000000000,
                 "scopes":["user:inference"],"subscriptionType":"max"}}"#,
        )
        .unwrap();

        let bearer = stored.into_bearer("Claude Code-credentials").unwrap();

        assert_eq!(bearer.token, "sk-ant-oat01-borrowed");
        assert_eq!(
            bearer.expires_at,
            Some(Timestamp::from_millisecond(1_788_521_737_675).unwrap())
        );
        let carried = serde_json::to_string(&bearer).unwrap();
        assert!(
            !carried.contains("ort01"),
            "the refresh token is what renews the researcher's own login, and renewing \
             rotates it: a session that spent it would log them out of their machine — \
             {carried}"
        );
    }

    #[test]
    fn a_login_that_is_not_a_subscription_is_refused_rather_than_half_used() {
        let stored: StoredLogin = serde_json::from_str(r#"{"someOtherProvider":{}}"#).unwrap();

        assert!(matches!(
            stored.into_bearer("Claude Code-credentials"),
            Err(AgentError::NotOauth { .. })
        ));
    }

    #[test]
    fn an_account_name_a_keychain_would_not_take_falls_back_the_way_claude_code_does() {
        assert!(is_account_character('a') && is_account_character('.'));
        assert!(!is_account_character('/'));
        assert_eq!(FALLBACK_ACCOUNT, "claude-code-user");
    }

    #[test]
    fn a_configuration_directory_of_its_own_earns_a_service_name_of_its_own() {
        // The digest Claude Code computes: the first four bytes of the SHA-256 of the
        // composed path, hex, appended to the plain name.
        let digest = Sha256::digest("/Users/researcher/.claude-work".as_bytes());
        let expected = format!(
            "{DEFAULT_SERVICE}-{:02x}{:02x}{:02x}{:02x}",
            digest[0], digest[1], digest[2], digest[3]
        );

        assert_eq!(expected.len(), DEFAULT_SERVICE.len() + 9);
        assert_ne!(expected, DEFAULT_SERVICE);
    }

    #[test]
    fn the_same_directory_spelled_two_ways_is_read_under_one_name() {
        let composed = "/Users/researcher/café";
        let decomposed = "/Users/researcher/cafe\u{301}";

        assert_ne!(composed, decomposed);
        assert_eq!(
            normalised(composed),
            normalised(decomposed),
            "macOS hands out decomposed paths where Finder has been, and a login found \
             under one spelling must be found under the other"
        );
    }
}
