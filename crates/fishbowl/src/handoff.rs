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

use std::ffi::OsString;

use askama::Template;
use fishbowl_image::SandboxLayout;

/// What the agent is told about the machine it is running on.
#[derive(Debug, Template)]
#[template(path = "briefing.txt", escape = "none")]
struct SessionBriefing<'a> {
    /// Directory work belongs in.
    work_dir: &'a str,
    /// Whether the session is a red team engagement — the briefing tells the agent the
    /// authorization was attested, and why refusal is not its call to make.
    redteam: bool,
    /// The `MalwareBazaar` key's variable, when the host has it set.
    malwarebazaar: Option<&'a str>,
}

/// The researcher's keys that this host holds, by the variables they are found in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handoff {
    /// The `MalwareBazaar` key, when the host holds it under a name the layout knows.
    malwarebazaar: Option<MalwareBazaarKey>,
}

/// A key the host holds, and the shape it crosses in.
///
/// `SendEnv` forwards a variable only under the name it holds in the client's own
/// environment, so a key found under an alias cannot ride under it: the client runs with
/// the alias's value replanted as `sent_as`, which is what [`Self::environment_aliases`]
/// records.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MalwareBazaarKey {
    /// The variable it is sent as — the layout's `malwarebazaar_key`, which the
    /// session's sshd accepts and the briefing names.
    sent_as: String,
    /// The variable it was found in on the host, when that is not the name it is sent as.
    found_as: Option<String>,
}

impl Handoff {
    /// Looks in this process's environment for each key the layout names.
    #[must_use]
    pub fn from_host(layout: &SandboxLayout) -> Self {
        Self::from_lookup(layout, |name| std::env::var_os(name).is_some())
    }

    /// Like [`Self::from_host`], but with `is_set` standing in for the environment.
    fn from_lookup(layout: &SandboxLayout, is_set: impl Fn(&str) -> bool) -> Self {
        let malwarebazaar = if is_set(&layout.malwarebazaar_key) {
            Some(MalwareBazaarKey {
                sent_as: layout.malwarebazaar_key.clone(),
                found_as: None,
            })
        } else {
            layout
                .malwarebazaar_key_aliases
                .iter()
                .find(|alias| is_set(alias))
                .map(|alias| MalwareBazaarKey {
                    sent_as: layout.malwarebazaar_key.clone(),
                    found_as: Some(alias.clone()),
                })
        };
        Self { malwarebazaar }
    }

    /// The variables ssh is asked to send along, which is every key that is set.
    #[must_use]
    pub fn sent(&self) -> Vec<String> {
        self.malwarebazaar
            .iter()
            .map(|key| key.sent_as.clone())
            .collect()
    }

    /// The aliases a client must run with for [`Self::sent`] to find them: pairs of the
    /// name a key is sent as and the name the host holds it under. A key already under
    /// its sent name is inherited by the client and needs nothing replanted.
    ///
    /// Only names are held; the values are read back out of the environment at spawn, so
    /// the credentials never sit in a value carried by either side.
    #[must_use]
    pub fn environment_aliases(&self) -> Vec<(OsString, OsString)> {
        self.malwarebazaar
            .iter()
            .filter_map(|key| {
                key.found_as
                    .as_ref()
                    .map(|alias| (OsString::from(&key.sent_as), OsString::from(alias)))
            })
            .collect()
    }

    /// What the agent is told about the machine it is running on, including any keys it
    /// has been given. `redteam` is the session's own settled posture — it comes from
    /// the record, never from an argument alone.
    ///
    /// # Panics
    /// Panics if the briefing template cannot be rendered, which the compiler already
    /// rules out for a template of plain string fields.
    #[must_use]
    pub fn briefing(&self, layout: &SandboxLayout, redteam: bool) -> String {
        let work_dir = layout.work_dir.display().to_string();
        SessionBriefing {
            work_dir: &work_dir,
            redteam,
            malwarebazaar: self.malwarebazaar.as_ref().map(|key| key.sent_as.as_str()),
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
            Some(MalwareBazaarKey {
                sent_as,
                found_as: Some(alias),
            }) => format!("{alias} from your environment, sent as {sent_as}"),
            Some(MalwareBazaarKey { sent_as, .. }) => {
                format!("{sent_as} from your environment")
            }
            None => "none set in your environment".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(names: &[&'static str]) -> impl Fn(&str) -> bool {
        move |name| names.contains(&name)
    }

    #[test]
    fn the_agent_is_told_it_is_disposable_and_how_samples_are_run() {
        let layout = SandboxLayout::default();
        let briefing = Handoff::from_lookup(&layout, |_| false).briefing(&layout, false);
        assert!(briefing.contains("disposable"));
        assert!(briefing.contains("`detonate`"));
        assert!(briefing.contains("no network"), "{briefing}");
        assert!(
            !briefing.contains("Auth-Key"),
            "a key that was not handed over is not described"
        );
        assert!(
            !briefing.contains("red team"),
            "an ordinary session's agent is not briefed as an engagement's operator"
        );
    }

    #[test]
    fn a_red_team_session_tells_the_agent_the_engagement_is_authorized() {
        let layout = SandboxLayout::default();
        let briefing = Handoff::from_lookup(&layout, |_| false).briefing(&layout, true);
        assert!(briefing.contains("red team engagement"), "{briefing}");
        assert!(
            briefing.contains("attested") && briefing.contains("authorization"),
            "the agent is told the authorization was settled, not merely asserted: \
             {briefing}"
        );
        assert!(
            briefing.contains("`detonate`"),
            "the sample rules still stand"
        );
    }

    #[test]
    fn a_key_the_host_has_is_sent_and_explained_and_one_it_lacks_is_neither() {
        let layout = SandboxLayout::default();
        let with = Handoff::from_lookup(&layout, environment(&["MALWAREBAZAAR_API_KEY"]));
        assert_eq!(with.sent(), vec!["MALWAREBAZAAR_API_KEY".to_owned()]);
        assert!(
            with.environment_aliases().is_empty(),
            "a key already under its session name needs nothing replanted"
        );
        let briefing = with.briefing(&layout, false);
        assert!(briefing.contains("MALWAREBAZAAR_API_KEY"));
        assert!(briefing.contains("Auth-Key"));

        let without = Handoff::from_lookup(&layout, |_| false);
        assert!(without.sent().is_empty());
    }

    #[test]
    fn a_key_the_host_holds_under_an_alias_is_replanted_under_the_session_name() {
        let layout = SandboxLayout::default();
        let handoff = Handoff::from_lookup(&layout, environment(&["MALWAREBAZAAR_AUTH_KEY"]));
        assert_eq!(
            handoff.sent(),
            vec!["MALWAREBAZAAR_API_KEY".to_owned()],
            "the session's sshd accepts the session's name and no other"
        );
        assert_eq!(
            handoff.environment_aliases(),
            vec![(
                OsString::from("MALWAREBAZAAR_API_KEY"),
                OsString::from("MALWAREBAZAAR_AUTH_KEY"),
            )],
            "SendEnv forwards a name only, so the alias's value is replanted under it"
        );
        assert!(
            handoff
                .briefing(&layout, false)
                .contains("MALWAREBAZAAR_API_KEY")
        );
        assert_eq!(
            handoff.summary(),
            "MALWAREBAZAAR_AUTH_KEY from your environment, sent as MALWAREBAZAAR_API_KEY"
        );
    }

    #[test]
    fn the_session_name_wins_over_an_alias_when_the_host_has_both() {
        let layout = SandboxLayout::default();
        let handoff = Handoff::from_lookup(
            &layout,
            environment(&["MALWAREBAZAAR_API_KEY", "MALWAREBAZAAR_AUTH_KEY"]),
        );
        assert!(
            handoff.environment_aliases().is_empty(),
            "a set canonical name is used as-is rather than overwritten by an alias"
        );
    }
}
