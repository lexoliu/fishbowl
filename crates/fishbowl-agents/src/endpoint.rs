use std::path::PathBuf;

/// One sandbox as the host's agents should reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxEndpoint {
    /// Stable identifier, also the sandbox's name.
    pub id: String,
    /// Account the agents log in as.
    pub user: String,
    /// Address the sandbox listens on, as seen from the host.
    pub host: String,
    /// Port sshd listens on.
    pub port: u16,
    /// Private key the host authenticates with.
    pub identity_file: PathBuf,
    /// File the sandbox's host key is remembered in.
    ///
    /// One per sandbox, kept beside its identity rather than in the user's own
    /// `known_hosts`. Sandboxes are handed vmnet addresses that outlive them, so two of
    /// them sharing the user's file would eventually disagree about who owns an address
    /// and ssh would refuse the connection until the user pruned the entry by hand.
    pub known_hosts: PathBuf,
    /// Directory the agents start in inside the sandbox.
    pub start_directory: PathBuf,
    /// Variables of the host's environment ssh is asked to send along.
    ///
    /// Sent rather than set: `SendEnv` takes the value from the client's own environment,
    /// so it never appears on a command line, and sends nothing for a name that is not
    /// set. The sandbox's sshd accepts the same names and no others.
    pub send_environment: Vec<String>,
}

impl SandboxEndpoint {
    /// `user@host`, the form both agents' SSH invocations take.
    #[must_use]
    pub fn destination(&self) -> String {
        format!("{}@{}", self.user, self.host)
    }

    /// The `ssh` arguments that reach the sandbox without touching the host's agent socket.
    ///
    /// Agent forwarding stays off: the sandbox is the untrusted side, and an agent socket
    /// reaching into it would undo the reason the credentials stay on the host.
    ///
    /// ssh is also told to say nothing below an error. SSH is how this tool reaches a
    /// session, not something the researcher asked for, and its running commentary — the
    /// host key it has just recorded, the connection it has just closed — names a
    /// mechanism they were never shown. What goes wrong is still reported.
    #[must_use]
    pub fn ssh_arguments(&self) -> Vec<String> {
        let mut arguments = vec![
            "-p".to_owned(),
            self.port.to_string(),
            "-i".to_owned(),
            self.identity_file.display().to_string(),
            "-o".to_owned(),
            "ForwardAgent=no".to_owned(),
            "-o".to_owned(),
            "LogLevel=ERROR".to_owned(),
            "-o".to_owned(),
            "StrictHostKeyChecking=accept-new".to_owned(),
            "-o".to_owned(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
        ];
        for name in &self.send_environment {
            arguments.push("-o".to_owned());
            arguments.push(format!("SendEnv={name}"));
        }
        arguments.push(self.destination());
        arguments
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::SandboxEndpoint;

    fn endpoint(id: &str) -> SandboxEndpoint {
        SandboxEndpoint {
            id: id.to_owned(),
            user: "researcher".to_owned(),
            host: "192.168.65.40".to_owned(),
            port: 22,
            identity_file: PathBuf::from("/state/keys").join(id),
            known_hosts: PathBuf::from("/state/known_hosts").join(id),
            start_directory: PathBuf::from("/work"),
            send_environment: vec!["MALWAREBAZAAR_API_KEY".to_owned()],
        }
    }

    fn option_of(arguments: &[String], name: &str) -> Option<String> {
        arguments
            .windows(2)
            .filter(|pair| pair[0] == "-o")
            .find_map(|pair| pair[1].strip_prefix(name).map(ToOwned::to_owned))
    }

    #[test]
    fn the_researchers_key_is_sent_by_name_and_never_by_value() {
        let arguments = endpoint("c0ffee").ssh_arguments();
        assert_eq!(
            option_of(&arguments, "SendEnv=").as_deref(),
            Some("MALWAREBAZAAR_API_KEY"),
            "the value comes from the client's environment, not from a command line \
             anyone on the host can list"
        );
        assert_eq!(
            arguments.last().map(String::as_str),
            Some("researcher@192.168.65.40"),
            "everything of ours goes before the destination"
        );
    }

    #[test]
    fn ssh_keeps_its_commentary_to_itself_but_still_reports_errors() {
        let arguments = endpoint("c0ffee").ssh_arguments();
        assert_eq!(
            option_of(&arguments, "LogLevel=").as_deref(),
            Some("ERROR"),
            "a researcher who never asked for ssh should not read about the host key it \
             recorded or the connection it closed, but must still hear what went wrong"
        );
    }

    #[test]
    fn a_sandbox_remembers_its_host_key_in_a_file_of_its_own() {
        assert_eq!(
            option_of(&endpoint("lab").ssh_arguments(), "UserKnownHostsFile=").as_deref(),
            Some("/state/known_hosts/lab"),
            "a sandbox's host key belongs beside its identity; writing it to the user's \
             own known_hosts leaves an entry behind for every machine we destroy"
        );
    }

    #[test]
    fn two_sandboxes_cannot_disagree_about_an_address_they_both_held() {
        let first = option_of(&endpoint("lab").ssh_arguments(), "UserKnownHostsFile=");
        let second = option_of(&endpoint("unpack").ssh_arguments(), "UserKnownHostsFile=");
        assert_ne!(
            first, second,
            "vmnet hands the same address to a later sandbox, so two of them sharing a \
             known-hosts file would make the second one look like an impostor"
        );
    }
}
