//! The agent state a session starts with, so that opening one is not a wizard.
//!
//! Claude Code asks a first-run question about the theme, another about trusting the
//! directory it was started in, and a third about running without approvals; Devin asks
//! to finish its shell setup and to trust the same directory. Every one of them is a
//! question about a machine cyber-sandbox made seconds earlier, on behalf of a
//! researcher who asked for exactly that machine — and a session that begins by asking
//! them is one nobody can hand to an agent and walk away from, which is the whole point of
//! running it in a sandbox.
//!
//! The answers are therefore written into the image, in the files each agent itself
//! keeps them in. Nothing here decides anything about permissions inside the session that
//! the sandbox does not already decide by being a sandbox.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::layout::SandboxLayout;

/// Colour scheme a session's Claude Code starts in.
///
/// The terminal it is displayed in belongs to the host, so this cannot be right for
/// everyone; it is the answer the first-run picker offers first, and `/theme` changes it.
const THEME: &str = "dark";

/// The model Claude Code opens on.
///
/// An alias rather than a dated identifier, so that the session follows the newest Opus
/// the way the researcher's own installation would, and does not fall behind when one is
/// retired.
const MODEL: &str = "opus";

/// Where the image installs the program Claude Code's status line runs.
pub const STATUS_LINE_PROGRAM: &str = "/usr/local/bin/cyber-sandbox-statusline";

/// `~/.claude.json`: the researcher account's Claude Code configuration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    has_completed_onboarding: bool,
    projects: BTreeMap<String, Project>,
}

/// One directory's entry in that configuration.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Project {
    has_trust_dialog_accepted: bool,
}

/// `~/.claude/settings.json`: the settings that are not per-directory.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    theme: &'static str,
    model: &'static str,
    skip_dangerous_mode_permission_prompt: bool,
    status_line: StatusLine,
}

/// `~/.config/devin/config.json`: the researcher account's Devin configuration.
///
/// `org_id` is deliberately absent: which organisation Devin belongs to is told to it by
/// the credentials it is lent, not written into an image ahead of them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DevinConfiguration {
    version: u8,
    shell: DevinShell,
    theme_mode: &'static str,
    agent: DevinAgent,
}

/// `shell`: whether Devin's own shell setup has been completed.
#[derive(Debug, Serialize)]
struct DevinShell {
    setup_complete: bool,
}

/// `agent`: which of the account's models Devin opens on.
#[derive(Debug, Serialize)]
struct DevinAgent {
    model: &'static str,
}

/// `~/.local/share/devin/cli/trusted_workspaces.json`: the directories Devin does not ask
/// about trusting.
///
/// A session's agent is only ever started in the work directory, so that is the only
/// path the file names — anything else trusted here would be trusted for samples too.
#[derive(Debug, Serialize)]
pub struct DevinWorkspaces {
    trusted_paths: Vec<String>,
}

/// `statusLine`: the command Claude Code runs to draw its status line.
///
/// A program of the image's rather than a shell string here, so that what the line says
/// is a file with a comment explaining it, and changing it does not mean editing JSON.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusLine {
    #[serde(rename = "type")]
    kind: &'static str,
    command: &'static str,
    padding: u8,
}

impl Configuration {
    /// The configuration a session's researcher account is given.
    ///
    /// The working directory is trusted because the researcher asked for the session it
    /// belongs to, and it is the only directory an agent is ever started in here.
    #[must_use]
    pub fn for_layout(layout: &SandboxLayout) -> Self {
        Self {
            has_completed_onboarding: true,
            projects: BTreeMap::from([(
                layout.work_dir.display().to_string(),
                Project {
                    has_trust_dialog_accepted: true,
                },
            )]),
        }
    }
}

impl Settings {
    /// The settings a session's researcher account is given.
    ///
    /// Approvals are off because the session is the sandbox: an agent that stops to ask
    /// for permission to read a file inside a machine built to contain it is one a
    /// researcher has to babysit for no gain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            theme: THEME,
            model: MODEL,
            skip_dangerous_mode_permission_prompt: true,
            status_line: StatusLine {
                kind: "command",
                command: STATUS_LINE_PROGRAM,
                padding: 0,
            },
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new()
    }
}

impl DevinConfiguration {
    /// The configuration a session's researcher account is given.
    ///
    /// The model is a family alias rather than a dated member, so the session opens on
    /// the family's strongest the way the researcher's own installation would — the same
    /// reasoning as Claude Code's `opus`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: 1,
            shell: DevinShell {
                setup_complete: true,
            },
            theme_mode: THEME,
            agent: DevinAgent { model: "swe-2" },
        }
    }
}

impl Default for DevinConfiguration {
    fn default() -> Self {
        Self::new()
    }
}

impl DevinWorkspaces {
    /// The trusted-workspaces file a session's researcher account is given.
    ///
    /// The working directory is trusted because the researcher asked for the session it
    /// belongs to, and it is the only directory an agent is ever started in here.
    #[must_use]
    pub fn for_layout(layout: &SandboxLayout) -> Self {
        Self {
            trusted_paths: vec![layout.work_dir.display().to_string()],
        }
    }
}
