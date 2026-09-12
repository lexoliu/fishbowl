//! Choosing a session to reopen.
//!
//! `--resume` with no value asks here, and the list is the only thing that ever decides
//! which environment gets reopened: there is no "most recent" shorthand, because the
//! machine a sample already ran in is not something to guess at on a researcher's behalf.

use std::fmt;

use anyhow::{Result, anyhow, bail};
use fishbowl_runtime::{ContainerState, RunState};
use inquire::{InquireError, Select};
use jiff::Timestamp;

use crate::session::{SessionRecord, describe_age};

/// How many sessions the picker shows before it starts scrolling.
const PAGE_SIZE: usize = 10;

/// Asks which of `sessions` to reopen.
///
/// # Errors
/// Fails when the terminal cannot be prompted, or when the researcher cancels — neither
/// is a session, and neither is a reason to pick one for them.
pub fn choose(sessions: Vec<SessionRecord>, live: &[ContainerState]) -> Result<SessionRecord> {
    let now = Timestamp::now();
    let choices = sessions
        .into_iter()
        .map(|record| Choice {
            label: label(&record, live, now),
            record,
        })
        .collect();

    match Select::new("Which session?", choices)
        .with_page_size(PAGE_SIZE)
        .prompt()
    {
        Ok(choice) => Ok(choice.record),
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            bail!("no session chosen")
        }
        Err(InquireError::NotTTY) => Err(anyhow!(
            "there is no terminal to pick a session in; name the one to reopen, as in \
             `--resume <session>`"
        )),
        Err(error) => Err(anyhow!(error).context("offering the host's sessions")),
    }
}

/// One row of the picker, which `inquire` renders through [`fmt::Display`].
struct Choice {
    record: SessionRecord,
    label: String,
}

impl fmt::Display for Choice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.label)
    }
}

/// What a session looks like in the list.
///
/// The state comes from the runtime rather than the record: a session whose machine is
/// stopped is still perfectly resumable, and one whose machine the runtime has forgotten
/// is not, so the difference belongs in front of the researcher before they choose.
fn label(record: &SessionRecord, live: &[ContainerState], now: Timestamp) -> String {
    let state = live
        .iter()
        .find(|container| container.id.as_str() == record.id.as_str())
        .map_or("gone", |container| match container.status.state {
            RunState::Running => "running",
            RunState::Stopped => "stopped",
            RunState::Starting => "starting",
            RunState::Stopping => "stopping",
        });
    let samples = record.samples.as_ref().map_or_else(
        || "no samples".to_owned(),
        |path| path.display().to_string(),
    );
    format!(
        "{:<8}{:<10}{:<12}{:<8}{samples}",
        record.id,
        state,
        describe_age(record.idle_for(now)),
        record.arch
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use fishbowl_runtime::{Arch, ImageReference};

    use super::*;

    /// Two machines as the runtime reports them: one running, one stopped.
    fn live() -> Vec<ContainerState> {
        serde_json::from_str(include_str!("../tests/data/containers.json")).unwrap()
    }

    fn record(id: &str) -> SessionRecord {
        SessionRecord {
            id: id.parse().unwrap(),
            image: ImageReference::new("localhost/fishbowl:arm64").unwrap(),
            arch: Arch::Arm64,
            ssh_port: 22,
            researcher: "researcher".to_owned(),
            work_dir: PathBuf::from("/work"),
            samples: None,
            identity_file: PathBuf::from("/keys/id"),
            created_at: Timestamp::now(),
            last_used: Timestamp::now(),
        }
    }

    #[test]
    fn a_stopped_session_is_offered_as_one_that_can_be_reopened() {
        let label = label(&record("dec0de"), &live(), Timestamp::now());
        assert!(
            label.contains("stopped"),
            "a stopped machine is restarted on resume, so it belongs in the list: {label}"
        );
    }

    #[test]
    fn a_session_the_runtime_has_forgotten_says_so_before_it_is_chosen() {
        let label = label(&record("abcdef"), &live(), Timestamp::now());
        assert!(
            label.contains("gone"),
            "resuming it will fail, and the researcher should read that in the list \
             rather than after choosing: {label}"
        );
    }

    #[test]
    fn every_column_of_a_row_is_separated_from_the_next() {
        let label = label(&record("c0ffee"), &live(), Timestamp::now());
        for column in ["c0ffee", "running", "arm64"] {
            let rest = &label[label.find(column).expect("column is in the row") + column.len()..];
            assert!(
                rest.starts_with(' '),
                "`{column}` runs straight into what follows it, which is unreadable: {label}"
            );
        }
    }
}
