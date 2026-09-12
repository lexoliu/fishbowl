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

use askama::Template;
use fishbowl_image::SandboxLayout;

/// What the agent is told about a key it has been given.
#[derive(Debug, Template)]
#[template(path = "malwarebazaar.txt", escape = "none")]
struct MalwareBazaarBriefing<'a> {
    variable: &'a str,
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

    /// What the agent is told about the keys it has been given, or nothing when it has
    /// been given none.
    ///
    /// # Panics
    /// Panics if the briefing template cannot be rendered, which the compiler already
    /// rules out for a template with one string field.
    #[must_use]
    pub fn briefing(&self) -> Option<String> {
        self.malwarebazaar.as_deref().map(|variable| {
            MalwareBazaarBriefing { variable }
                .render()
                .expect("a one-field briefing renders")
                .trim_end()
                .to_owned()
        })
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
    fn a_key_the_host_has_is_sent_and_explained_and_one_it_lacks_is_neither() {
        let layout = SandboxLayout::default();
        let with = Handoff::from_lookup(&layout, |_| true);
        assert_eq!(with.sent(), vec!["MALWAREBAZAAR_API_KEY".to_owned()]);
        let briefing = with.briefing().unwrap();
        assert!(briefing.contains("MALWAREBAZAAR_API_KEY"));
        assert!(briefing.contains("Auth-Key"));
        assert!(
            briefing.contains("`detonate`"),
            "an agent told about a way to fetch samples is told how they are run here"
        );

        let without = Handoff::from_lookup(&layout, |_| false);
        assert!(without.sent().is_empty());
        assert_eq!(without.briefing(), None);
    }
}
