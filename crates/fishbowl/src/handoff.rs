//! What of the researcher's own environment a session is handed.
//!
//! A researcher analysing malware has accounts of their own — `MalwareBazaar`'s above all —
//! and the key for one is something they want in the session, where the tools that use
//! it run. It is theirs to hand over, so the switch is theirs too: a variable set on the
//! host is passed, a variable not set is not, and no flag or setting stands between.
//!
//! What crosses is the variable, in the researcher account's environment and nowhere
//! else. Samples run as another account, and `sudo` resets the environment on the way
//! there, so a key handed to the session is not thereby handed to the sample.
//!
//! Whatever is handed over, the agent is told what kind of machine it is running on: a
//! disposable one it can act on freely, where samples are executed through `detonate`
//! and get no network. What it is not told is how its egress is observed — the audit is
//! the host's to read, not the agent's to think about.

use askama::Template;
use fishbowl_image::SandboxLayout;

/// What the agent is told about the machine it is running on.
#[derive(Debug, Template)]
#[template(path = "briefing.txt", escape = "none")]
struct SessionBriefing<'a> {
    /// Directory work belongs in.
    work_dir: &'a str,
    /// The `MalwareBazaar` key's variable, when the host has it set.
    malwarebazaar: Option<&'a str>,
}

/// The researcher's keys that this host holds, by the variables they are found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    /// The `MalwareBazaar` key's variable, when the host has it set.
    malwarebazaar: Option<String>,
}

impl Handoff {
    /// Looks in this process's environment for each key the layout names.
    #[must_use]
    pub fn from_host(layout: &SandboxLayout) -> Self {
        Self::from_lookup(layout, |name| std::env::var_os(name).is_some())
    }

    /// Like [`Self::from_host`], but with `is_set` standing in for the environment.
    fn from_lookup(layout: &SandboxLayout, is_set: impl Fn(&str) -> bool) -> Self {
        Self {
            malwarebazaar: is_set(&layout.malwarebazaar_key)
                .then(|| layout.malwarebazaar_key.clone()),
        }
    }

    /// The variables ssh is asked to send along, which is every key that is set.
    #[must_use]
    pub fn sent(&self) -> Vec<String> {
        self.malwarebazaar.iter().cloned().collect()
    }

    /// What the agent is told about the machine it is running on, including any keys it
    /// has been given.
    ///
    /// # Panics
    /// Panics if the briefing template cannot be rendered, which the compiler already
    /// rules out for a template of plain string fields.
    #[must_use]
    pub fn briefing(&self, layout: &SandboxLayout) -> String {
        let work_dir = layout.work_dir.display().to_string();
        SessionBriefing {
            work_dir: &work_dir,
            malwarebazaar: self.malwarebazaar.as_deref(),
        }
        .render()
        .expect("a briefing of plain strings renders")
        .trim_end()
        .to_owned()
    }

    /// One line for the session summary.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.malwarebazaar {
            Some(variable) => format!("{variable} from your environment"),
            None => "none set in your environment".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_agent_is_told_it_is_disposable_and_how_samples_are_run() {
        let layout = SandboxLayout::default();
        let briefing = Handoff::from_lookup(&layout, |_| false).briefing(&layout);
        assert!(briefing.contains("disposable"));
        assert!(briefing.contains("`detonate`"));
        assert!(briefing.contains("no network"), "{briefing}");
        assert!(
            !briefing.contains("Auth-Key"),
            "a key that was not handed over is not described"
        );
    }

    #[test]
    fn a_key_the_host_has_is_sent_and_explained_and_one_it_lacks_is_neither() {
        let layout = SandboxLayout::default();
        let with = Handoff::from_lookup(&layout, |_| true);
        assert_eq!(with.sent(), vec!["MALWAREBAZAAR_API_KEY".to_owned()]);
        let briefing = with.briefing(&layout);
        assert!(briefing.contains("MALWAREBAZAAR_API_KEY"));
        assert!(briefing.contains("Auth-Key"));

        let without = Handoff::from_lookup(&layout, |_| false);
        assert!(without.sent().is_empty());
    }
}
