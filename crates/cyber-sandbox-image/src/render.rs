use askama::Template;
use cyber_sandbox_runtime::Arch;

use crate::{
    guest::GUEST_CRATES,
    layout::SandboxLayout,
    onboarding::{Configuration, DevinConfiguration, DevinWorkspaces, Settings},
    openssh::OpenSshBuild,
    profile::ToolProfile,
};

/// The image definition itself.
#[derive(Debug, Template)]
#[template(path = "Dockerfile", escape = "none")]
pub struct Dockerfile {
    /// Kali image the sandbox derives from.
    pub base_image: String,
    /// Packages to install.
    pub packages: Vec<String>,
    /// Researcher account name.
    pub researcher_user: String,
    /// Researcher uid.
    pub researcher_uid: u32,
    /// Researcher gid.
    pub researcher_gid: u32,
    /// Detonation account name.
    pub detonate_user: String,
    /// Detonation uid.
    pub detonate_uid: u32,
    /// Detonation gid.
    pub detonate_gid: u32,
    /// Gateway account name.
    pub gateway_user: String,
    /// Gateway uid.
    pub gateway_uid: u32,
    /// Gateway gid.
    pub gateway_gid: u32,
    /// Home directory created for the gateway account.
    pub gateway_home: String,
    /// Directory the audit trail is written into.
    pub audit_directory: String,
    /// Read-only mount point holding samples under analysis.
    pub samples_dir: String,
    /// Writable working directory for the researcher account.
    pub work_dir: String,
    /// npm packages providing the agents' in-sandbox tool side.
    pub agent_packages: String,
    /// The workspace members compiled into the image, as `cargo build -p` arguments.
    pub guest_crates: String,
    /// Where the program Claude Code's status line runs is installed.
    pub status_line_program: &'static str,
    /// The OpenSSH release this image compiles its own sshd from, where the packaged one
    /// cannot serve the guest.
    pub openssh: Option<OpenSshBuild>,
}

/// The one rule letting the researcher account become the detonation account.
#[derive(Debug, Template)]
#[template(path = "sudoers", escape = "none")]
pub struct Sudoers {
    /// Researcher account name, the only account the rule is written for.
    pub researcher_user: String,
    /// Detonation account name, the only account the rule leads to.
    pub detonate_user: String,
}

/// The wrapper a sample is started through.
#[derive(Debug, Template)]
#[template(path = "detonate.sh", escape = "none")]
pub struct Detonate {
    /// Researcher account name.
    pub researcher_user: String,
    /// Detonation account name.
    pub detonate_user: String,
}

/// The packet filter policy applied before `CAP_NET_ADMIN` is dropped.
#[derive(Debug, Template)]
#[template(path = "egress-policy.sh", escape = "none")]
pub struct EgressPolicy {
    /// Gateway uid, exempted from redirection.
    pub gateway_uid: u32,
    /// Transparent proxy port.
    pub proxy_port: u16,
    /// Intercepting resolver port.
    pub dns_port: u16,
    /// Port sshd listens on.
    pub ssh_port: u16,
    /// NFLOG group refused packets are reported on.
    pub nflog_group: u16,
}

/// The container's init script.
#[derive(Debug, Template)]
#[template(path = "entrypoint.sh", escape = "none")]
pub struct Entrypoint {
    /// Gateway account name.
    pub gateway_user: String,
    /// Audit trail path.
    pub audit_trail: String,
    /// Gateway CA certificate path.
    pub ca_certificate: String,
    /// Authorized keys file the entrypoint writes the host's public key into.
    pub authorized_keys: String,
    /// Directory work happens in, which the agent's path is aliased to.
    pub work_dir: String,
    /// Researcher account name, which owns the runtime directory.
    pub researcher_user: String,
    /// Directory the host's per-attachment sockets and credential files live in.
    pub runtime_dir: String,
    /// Transparent proxy port.
    pub proxy_port: u16,
    /// Intercepting resolver port.
    pub dns_port: u16,
    /// NFLOG group refused packets are reported on.
    pub nflog_group: u16,
}

/// The sshd drop-in that exposes the agent control plane and nothing else.
#[derive(Debug, Template)]
#[template(path = "sshd_config", escape = "none")]
pub struct SshdConfig {
    /// Port sshd listens on.
    pub ssh_port: u16,
    /// Authorized keys file for the researcher account.
    pub authorized_keys: String,
    /// Researcher account name.
    pub researcher_user: String,
    /// The one variable of the researcher's own that sshd accepts from the host.
    pub malwarebazaar_key: String,
}

/// Every generated file that makes up the image build context.
#[derive(Debug)]
pub struct RenderedImage {
    /// Contents of `Dockerfile`.
    pub dockerfile: String,
    /// Contents of `entrypoint.sh`.
    pub entrypoint: String,
    /// Contents of `egress-policy.sh`.
    pub egress_policy: String,
    /// Contents of `sshd_config`.
    pub sshd_config: String,
    /// Contents of the researcher account's `~/.claude.json`.
    pub claude_config: String,
    /// Contents of the researcher account's `~/.claude/settings.json`.
    pub claude_settings: String,
    /// Contents of the researcher account's `~/.config/devin/config.json`.
    pub devin_config: String,
    /// Contents of the researcher account's
    /// `~/.local/share/devin/cli/trusted_workspaces.json`.
    pub devin_trusted_workspaces: String,
    /// Contents of the sudoers drop-in.
    pub sudoers: String,
    /// Contents of the program Claude Code's status line runs.
    pub statusline: &'static str,
    /// Contents of the `detonate` wrapper.
    pub detonate: String,
}

impl RenderedImage {
    /// Renders every generated file from one layout, architecture and profile.
    ///
    /// # Errors
    /// Fails only when a template is malformed, which the compiler already rejects, or
    /// when rendering runs out of memory.
    ///
    /// # Panics
    /// Panics if the agent configuration cannot be serialised, which would mean a struct
    /// in [`crate::onboarding`] had grown a field serde cannot represent as JSON.
    pub fn render(
        base_image: &str,
        arch: Arch,
        profile: ToolProfile,
        layout: &SandboxLayout,
    ) -> Result<Self, askama::Error> {
        let dockerfile = Dockerfile {
            base_image: base_image.to_owned(),
            packages: profile.packages(),
            researcher_user: layout.researcher.name.clone(),
            researcher_uid: layout.researcher.uid,
            researcher_gid: layout.researcher.gid,
            detonate_user: layout.detonate.name.clone(),
            detonate_uid: layout.detonate.uid,
            detonate_gid: layout.detonate.gid,
            gateway_user: layout.gateway.name.clone(),
            gateway_uid: layout.gateway.uid,
            gateway_gid: layout.gateway.gid,
            gateway_home: layout.gateway_home.display().to_string(),
            audit_directory: layout.audit_directory().display().to_string(),
            samples_dir: layout.samples_dir.display().to_string(),
            work_dir: layout.work_dir.display().to_string(),
            agent_packages: crate::profile::AGENT_PACKAGES.join(" "),
            guest_crates: GUEST_CRATES
                .iter()
                .map(|name| format!("-p {name}"))
                .collect::<Vec<_>>()
                .join(" "),
            status_line_program: crate::onboarding::STATUS_LINE_PROGRAM,
            openssh: OpenSshBuild::required_for(arch),
        }
        .render()?;
        let egress_policy = EgressPolicy {
            gateway_uid: layout.gateway.uid,
            proxy_port: layout.proxy_port,
            dns_port: layout.dns_port,
            ssh_port: layout.ssh_port,
            nflog_group: layout.nflog_group,
        }
        .render()?;
        let entrypoint = Entrypoint {
            gateway_user: layout.gateway.name.clone(),
            audit_trail: layout.audit_trail().display().to_string(),
            ca_certificate: layout.ca_certificate().display().to_string(),
            authorized_keys: layout.authorized_keys.display().to_string(),
            work_dir: layout.work_dir.display().to_string(),
            researcher_user: layout.researcher.name.clone(),
            runtime_dir: layout.runtime_dir.display().to_string(),
            proxy_port: layout.proxy_port,
            dns_port: layout.dns_port,
            nflog_group: layout.nflog_group,
        }
        .render()?;
        let sshd_config = SshdConfig {
            ssh_port: layout.ssh_port,
            authorized_keys: layout.authorized_keys.display().to_string(),
            researcher_user: layout.researcher.name.clone(),
            malwarebazaar_key: layout.malwarebazaar_key.clone(),
        }
        .render()?;
        let sudoers = Sudoers {
            researcher_user: layout.researcher.name.clone(),
            detonate_user: layout.detonate.name.clone(),
        }
        .render()?;
        let detonate = Detonate {
            researcher_user: layout.researcher.name.clone(),
            detonate_user: layout.detonate.name.clone(),
        }
        .render()?;
        let claude_config = serde_json::to_string_pretty(&Configuration::for_layout(layout))
            .expect("the agent configuration is representable as JSON");
        let claude_settings = serde_json::to_string_pretty(&Settings::new())
            .expect("the agent settings are representable as JSON");
        let devin_config = serde_json::to_string_pretty(&DevinConfiguration::new())
            .expect("the agent configuration is representable as JSON");
        let devin_trusted_workspaces =
            serde_json::to_string_pretty(&DevinWorkspaces::for_layout(layout))
                .expect("the agent's trusted workspaces are representable as JSON");
        Ok(Self {
            dockerfile,
            entrypoint,
            egress_policy,
            sshd_config,
            claude_config,
            claude_settings,
            devin_config,
            devin_trusted_workspaces,
            sudoers,
            detonate,
            statusline: include_str!("../templates/statusline.sh"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn for_arch(arch: Arch) -> RenderedImage {
        RenderedImage::render(
            "docker.io/kalilinux/kali-rolling:latest",
            arch,
            ToolProfile::Core,
            &SandboxLayout::default(),
        )
        .unwrap()
    }

    fn rendered() -> RenderedImage {
        for_arch(Arch::Arm64)
    }

    #[test]
    fn the_gateway_uid_is_the_only_uid_exempt_from_redirection() {
        let policy = rendered().egress_policy;
        assert!(policy.contains("readonly GATEWAY_UID=65001"));
        assert!(policy.contains("--uid-owner \"${GATEWAY_UID}\" -j RETURN"));
    }

    #[test]
    fn redirected_traffic_is_accepted_only_at_the_gateway_ports() {
        let policy = rendered().egress_policy;
        // The redirection rewrites the destination to the loopback address, so this is
        // the rule that lets audited traffic out at all. Without it the default drop
        // swallows every connection the gateway was supposed to see.
        assert!(policy.contains("-p tcp -d 127.0.0.1 --dport \"${PROXY_PORT}\" -j ACCEPT"));
        assert!(policy.contains("-p udp -d 127.0.0.1 --dport \"${DNS_PORT}\" -j ACCEPT"));
    }

    #[test]
    fn every_output_chain_defaults_to_drop() {
        let policy = rendered().egress_policy;
        for chain in ["iptables -P OUTPUT DROP", "ip6tables -P OUTPUT DROP"] {
            assert!(policy.contains(chain), "missing default drop: {chain}");
        }
    }

    #[test]
    fn nothing_but_the_gateway_and_loopback_is_accepted_on_the_way_out() {
        let policy = rendered().egress_policy;
        let accepts: Vec<&str> = policy
            .lines()
            .filter(|line| line.starts_with("iptables -A OUTPUT") && line.ends_with("-j ACCEPT"))
            .collect();
        assert_eq!(
            accepts,
            vec![
                "iptables -A OUTPUT -o lo -j ACCEPT",
                "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                "iptables -A OUTPUT -m owner --uid-owner \"${GATEWAY_UID}\" -j ACCEPT",
                "iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport \"${PROXY_PORT}\" -j ACCEPT",
                "iptables -A OUTPUT -p udp -d 127.0.0.1 --dport \"${DNS_PORT}\" -j ACCEPT",
            ],
            "every accept is matched by interface, uid, connection state, or the \
             loopback destination the redirection itself wrote; an accept matched by \
             protocol alone would let traffic the redirection missed leave unaudited"
        );
    }

    #[test]
    fn the_agents_working_directory_is_a_link_into_the_sandbox_rather_than_a_mount() {
        let entrypoint = rendered().entrypoint;
        assert!(
            entrypoint.contains(r#"ln -sfn "${WORK_DIR}" "${CYBER_SANDBOX_WORK_ALIAS}""#),
            "an agent resolves its working directory on the host and then asks the sandbox \
             to execute there, so the path it resolved has to name the work directory here \
             — and as a link rather than a mount, so nothing of the host's is shared: \
             {entrypoint}"
        );
    }

    #[test]
    fn the_entrypoint_drops_net_admin_before_running_anything_untrusted() {
        let entrypoint = rendered().entrypoint;
        let policy_at = entrypoint.find("egress-policy.sh").unwrap();
        let drop_at = entrypoint.find("capsh --drop=cap_net_admin").unwrap();
        let sshd_at = entrypoint.find("/usr/sbin/sshd").unwrap();
        assert!(
            policy_at < drop_at && drop_at < sshd_at,
            "the policy must be installed, then NET_ADMIN dropped, then sshd started"
        );
    }

    #[test]
    fn the_host_public_key_is_installed_by_root_before_sshd_starts() {
        let entrypoint = rendered().entrypoint;
        let write_at = entrypoint
            .find("printf '%s\\n' \"${CYBER_SANDBOX_AUTHORIZED_KEY}\"")
            .unwrap();
        let sshd_at = entrypoint.find("/usr/sbin/sshd").unwrap();
        assert!(write_at < sshd_at);
        assert!(
            entrypoint.contains("readonly AUTHORIZED_KEYS=/etc/ssh/authorized_keys.d/researcher"),
            "{entrypoint}"
        );
    }

    #[test]
    fn the_authority_is_installed_before_the_gateway_starts_serving() {
        let entrypoint = rendered().entrypoint;
        let init_at = entrypoint.find("init-ca").unwrap();
        let install_at = entrypoint.find("update-ca-certificates").unwrap();
        let serve_at = entrypoint.find("serve \\").unwrap();
        assert!(
            init_at < install_at && install_at < serve_at,
            "the trust store must hold the authority before any traffic can flow"
        );
    }

    #[test]
    fn only_the_gateway_account_can_execute_the_binary_that_carries_a_capability() {
        let dockerfile = rendered().dockerfile;
        assert!(
            dockerfile.contains("setcap cap_net_admin+ep /usr/local/bin/cyber-sandbox-gateway")
        );
        assert!(dockerfile.contains("chmod 0050 /usr/local/bin/cyber-sandbox-gateway"));
        assert!(
            dockerfile.contains("chown root:gateway /usr/local/bin/cyber-sandbox-gateway"),
            "{dockerfile}"
        );
    }

    #[test]
    fn the_first_run_questions_are_answered_for_the_directory_the_agent_opens_in() {
        let layout = SandboxLayout::default();
        let rendered = rendered();
        let configuration: serde_json::Value =
            serde_json::from_str(&rendered.claude_config).unwrap();
        assert_eq!(configuration["hasCompletedOnboarding"], true);
        assert_eq!(
            configuration["projects"][layout.work_dir.to_str().unwrap()]["hasTrustDialogAccepted"],
            true,
            "the directory is one this image made, and being asked to trust it would \
             stop an agent nobody is sitting in front of"
        );

        let settings: serde_json::Value = serde_json::from_str(&rendered.claude_settings).unwrap();
        assert_eq!(settings["skipDangerousModePermissionPrompt"], true);
        assert_eq!(
            settings["model"], "opus",
            "the session opens on the strongest model rather than on whatever the \
             installation defaults to that week"
        );
        assert_eq!(settings["statusLine"]["type"], "command");
        assert_eq!(
            settings["statusLine"]["command"],
            crate::onboarding::STATUS_LINE_PROGRAM,
            "the status line is drawn by a program the image installs, so the two have to \
             agree on where"
        );
        assert!(rendered.statusline.contains("printf 'Cyber sandbox"));
        assert!(
            rendered.dockerfile.contains(&format!(
                "COPY statusline.sh {}",
                crate::onboarding::STATUS_LINE_PROGRAM
            )),
            "{}",
            rendered.dockerfile
        );
        assert!(
            settings["theme"].is_string(),
            "an unanswered theme is a picker the session opens on instead of the work"
        );
    }

    #[test]
    fn devins_first_run_questions_are_answered_and_its_binary_is_installed() {
        let layout = SandboxLayout::default();
        let rendered = rendered();

        let configuration: serde_json::Value =
            serde_json::from_str(&rendered.devin_config).unwrap();
        assert_eq!(configuration["shell"]["setup_complete"], true);
        assert_eq!(
            configuration["agent"]["model"], "swe-2",
            "a family alias, so the session follows the family's strongest rather than a \
             member pinned the week the image was written"
        );
        assert!(
            configuration.get("org_id").is_none(),
            "which organisation Devin belongs to is told by the lent credentials, not \
             written ahead of them"
        );

        let workspaces: serde_json::Value =
            serde_json::from_str(&rendered.devin_trusted_workspaces).unwrap();
        assert_eq!(
            workspaces["trusted_paths"],
            serde_json::json!([layout.work_dir.display().to_string()]),
            "the only directory an agent is ever started in is the only one trusted"
        );

        let dockerfile = &rendered.dockerfile;
        let user_at = dockerfile.find("USER ").unwrap();
        let install_at = dockerfile.find("cli.devin.ai/install.sh").unwrap();
        let root_at = dockerfile.find("USER root").unwrap();
        assert!(
            user_at < install_at
                && install_at < root_at
                && dockerfile[user_at..install_at].contains("researcher"),
            "the installer must run as the researcher so the self-updater can write \
             beside the binary it lands: {dockerfile}"
        );
        assert!(
            dockerfile.contains("test -x /home/researcher/.local/bin/devin"),
            "a build that fails here fails loudly; a session that finds no binary fails \
             silently after a minute's boot"
        );
        assert!(
            dockerfile
                .contains("COPY devin-config.json /home/researcher/.config/devin/config.json")
        );
        assert!(dockerfile.contains("COPY devin-trusted-workspaces.json"));
        assert!(
            dockerfile.contains("/home/researcher/.local/share/devin/cli/trusted_workspaces.json")
        );
    }

    #[test]
    fn the_answers_are_installed_where_the_agent_reads_them() {
        let dockerfile = rendered().dockerfile;
        assert!(dockerfile.contains("COPY claude.json /home/researcher/.claude.json"));
        assert!(
            dockerfile.contains("COPY claude-settings.json /home/researcher/.claude/settings.json")
        );
        assert!(
            dockerfile.contains("chmod 0600 /home/researcher/.claude.json"),
            "the file the agent's own settings live in is not one other accounts in the \
             session should be able to rewrite"
        );
    }

    #[test]
    fn a_sample_and_a_borrowed_token_never_share_a_uid() {
        let layout = SandboxLayout::default();
        assert_ne!(layout.detonate.uid, layout.researcher.uid);
        assert_ne!(layout.detonate.uid, layout.gateway.uid);
        assert!(
            (65000..=65533).contains(&layout.detonate.uid),
            "outside the band Debian reserves, a base image could already hold this uid"
        );
    }

    #[test]
    fn the_only_account_a_sample_can_become_is_the_one_it_started_as() {
        let rendered = rendered();
        let rules: Vec<&str> = rendered
            .sudoers
            .lines()
            .filter(|line| !line.trim_start().starts_with('#') && !line.trim().is_empty())
            .collect();
        assert_eq!(
            rules,
            vec!["researcher ALL=(detonate:detonate) NOPASSWD: ALL"],
            "one rule, naming one account on each side: anything else is a way out of \
             the uid a sample was started under"
        );
        assert!(
            !rendered.sudoers.contains("(ALL"),
            "a rule whose right-hand side is ALL includes root: {}",
            rendered.sudoers
        );
    }

    #[test]
    fn a_sample_is_started_as_the_account_that_owns_nothing() {
        let detonate = rendered().detonate;
        assert!(detonate.contains("exec sudo --non-interactive --user detonate --"));
        assert!(
            !detonate.contains("--preserve-env"),
            "sudo resets the environment, which is what keeps an agent's token out of \
             the sample it starts: {detonate}"
        );
    }

    #[test]
    fn what_the_agent_holds_is_out_of_the_samples_reach() {
        let dockerfile = rendered().dockerfile;
        assert!(
            dockerfile.contains("chmod 0700 /home/researcher"),
            "the agent's settings and every conversation it has had here live under that \
             directory"
        );
        assert!(
            dockerfile.contains("visudo -cs -f /etc/sudoers.d/cyber-sandbox"),
            "a rule that does not parse would leave the session unable to detonate at all"
        );
        assert!(dockerfile.contains("chmod 0440 /etc/sudoers.d/cyber-sandbox"));
    }

    #[test]
    fn the_headless_profile_adds_the_kali_metapackage() {
        assert!(
            ToolProfile::Headless
                .packages()
                .contains(&"kali-linux-headless".to_owned())
        );
        assert!(
            !ToolProfile::Core
                .packages()
                .contains(&"kali-linux-headless".to_owned())
        );
    }

    #[test]
    fn the_courier_is_built_from_the_same_tree_and_installed_for_the_researcher() {
        let dockerfile = rendered().dockerfile;
        assert!(
            dockerfile.contains("-p cyber-sandbox-gateway -p cyber-sandbox-courier"),
            "the courier writes the credentials file the host's own crate defines, so \
             building it from anything but this tree would let the two formats drift: \
             {dockerfile}"
        );
        assert!(
            dockerfile.contains("/src/target/release/cyber-sandbox-courier"),
            "{dockerfile}"
        );
        assert!(
            !dockerfile.contains("setcap cap_net_admin+ep /usr/local/bin/cyber-sandbox-courier"),
            "the courier holds a credential and must therefore hold no privilege"
        );
    }

    #[test]
    fn the_credential_lands_somewhere_only_the_researcher_account_can_reach() {
        let entrypoint = rendered().entrypoint;
        assert!(
            entrypoint.contains("install -d -o researcher -g researcher -m 0700"),
            "a mode any wider would let a sample running beside the agent read the token \
             out of the file, or take it by connecting to the socket: {entrypoint}"
        );
        let make_at = entrypoint.find("\"${RUNTIME_DIR}\"").unwrap();
        let sshd_at = entrypoint.find("/usr/sbin/sshd").unwrap();
        assert!(
            make_at < sshd_at,
            "sshd binds the forwarded socket before the command runs, so the directory \
             has to exist before sshd does"
        );
    }

    #[test]
    fn the_only_variables_accepted_over_ssh_are_the_locale_and_the_researchers_own_key() {
        let config = rendered().sshd_config;
        let accepted = config
            .lines()
            .find(|line| line.starts_with("AcceptEnv"))
            .unwrap();
        assert_eq!(
            accepted, "AcceptEnv LANG LC_* MALWAREBAZAAR_API_KEY",
            "an agent's borrowed token is not accepted here — the courier puts it in one \
             process's environment — and the researcher's own key is accepted by name, so \
             nothing else the host has set can follow it in"
        );
    }

    #[test]
    fn a_socket_left_by_a_killed_attachment_does_not_block_the_next_one() {
        assert!(rendered().sshd_config.contains("StreamLocalBindUnlink yes"));
    }

    #[test]
    fn sshd_permits_only_remote_stream_local_forwarding() {
        let config = rendered().sshd_config;
        assert!(config.contains("AllowStreamLocalForwarding remote"));
        assert!(config.contains("AllowTcpForwarding no"));
        assert!(config.contains("PermitRootLogin no"));
        assert!(config.contains("PasswordAuthentication no"));
    }

    #[test]
    fn a_native_image_keeps_the_packaged_sshd() {
        let dockerfile = for_arch(Arch::Arm64).dockerfile;
        assert!(
            !dockerfile.contains("AS sshd"),
            "the packaged sshd's seccomp sandbox works natively, and is the stronger one, \
             so nothing is compiled: {dockerfile}"
        );
        assert!(!dockerfile.contains("--with-sandbox"));
    }

    #[test]
    fn a_translated_image_compiles_an_sshd_that_can_enter_its_own_sandbox() {
        let build = OpenSshBuild::required_for(Arch::Amd64).unwrap();
        let dockerfile = for_arch(Arch::Amd64).dockerfile;
        assert!(
            dockerfile.contains(&format!("--with-sandbox={}", build.sandbox())),
            "the mechanism is a configure-time choice with no sshd_config keyword, so it \
             has to be written here or the packaged sshd's seccomp filter is what runs: \
             {dockerfile}"
        );
        assert!(
            dockerfile.contains(&format!("openssh-{}.tar.gz", build.version()))
                && dockerfile.contains(build.sha256()),
            "the release is pinned by version and checksum"
        );
        assert!(
            dockerfile.contains("sha256sum --check --strict"),
            "an unpinned tarball must fail the build, not reach the sandbox"
        );
    }

    #[test]
    fn the_compiled_sshd_replaces_every_binary_of_the_privilege_separation_chain() {
        let dockerfile = for_arch(Arch::Amd64).dockerfile;
        for binary in [
            "COPY --from=sshd /out/usr/sbin/sshd /usr/sbin/sshd",
            "COPY --from=sshd /out/usr/lib/openssh/sshd-session /usr/lib/openssh/sshd-session",
            "COPY --from=sshd /out/usr/lib/openssh/sshd-auth /usr/lib/openssh/sshd-auth",
        ] {
            assert!(dockerfile.contains(binary), "missing {binary}");
        }
        assert!(
            !dockerfile.contains("/out/etc"),
            "the configuration files stay Kali's: our drop-in is only read because \
             its sshd_config carries the include that reads it"
        );
        let install_at = dockerfile.find("apt-get install").unwrap();
        let copy_at = dockerfile.find("COPY --from=sshd").unwrap();
        assert!(
            install_at < copy_at,
            "the copy has to land after the package that ships the binaries it replaces"
        );
    }
}
