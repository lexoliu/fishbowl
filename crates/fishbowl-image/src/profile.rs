use serde::{Deserialize, Serialize};

/// npm packages providing the agents that run inside the sandbox.
///
/// Codex's is only its exec-server — the model side, and with it the credential, stays on
/// the host. Claude Code's is the whole agent, lent a token for as long as it runs. Devin
/// is not here at all: it is no npm package, and the image installs it by its own
/// installer instead.
pub const AGENT_PACKAGES: &[&str] = &["@anthropic-ai/claude-code", "@openai/codex"];

/// Packages every sandbox needs regardless of profile: the control plane, the egress
/// policy's own tooling, and the runtimes the two agents are written in.
const BASE: &[&str] = &[
    "bash",
    "ca-certificates",
    "curl",
    "git",
    "iproute2",
    "iptables",
    "jq",
    "less",
    "libcap2-bin",
    "nodejs",
    "npm",
    "openssh-server",
    "python3",
    "python3-pip",
    "python3-venv",
    "ripgrep",
    "sudo",
    "tmux",
    "util-linux",
    "vim",
    "wget",
];

/// A curated analysis toolchain that stays small enough to rebuild quickly.
const CORE_TOOLS: &[&str] = &[
    "binutils",
    "binwalk",
    "clamav",
    "dnsutils",
    "exiftool",
    "file",
    "foremost",
    "gdb",
    "gdb-multiarch",
    "ltrace",
    "netcat-openbsd",
    "nmap",
    "oletools",
    "patchelf",
    "radare2",
    "socat",
    "sleuthkit",
    "strace",
    "tcpdump",
    "tshark",
    "upx-ucl",
    "yara",
];

/// How much of the Kali toolchain the image installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolProfile {
    /// A curated set covering static analysis, debugging, network capture and forensics.
    Core,
    /// Everything in [`ToolProfile::Core`] plus the `kali-linux-headless` metapackage.
    Headless,
}

/// A tool profile name that is not one of the two the image knows how to build.
#[derive(Debug, thiserror::Error)]
#[error("`{0}` is not a tool profile; expected `core` or `headless`")]
pub struct UnknownProfile(String);

impl std::str::FromStr for ToolProfile {
    type Err = UnknownProfile;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "core" => Ok(Self::Core),
            "headless" => Ok(Self::Headless),
            other => Err(UnknownProfile(other.to_owned())),
        }
    }
}

impl std::fmt::Display for ToolProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Core => "core",
            Self::Headless => "headless",
        })
    }
}

impl ToolProfile {
    /// The apt packages this profile installs, in the order the image installs them.
    #[must_use]
    pub fn packages(self) -> Vec<String> {
        let mut packages: Vec<String> = BASE
            .iter()
            .chain(CORE_TOOLS)
            .map(|package| (*package).to_owned())
            .collect();
        if self == Self::Headless {
            packages.push("kali-linux-headless".to_owned());
        }
        packages.sort_unstable();
        packages.dedup();
        packages
    }
}
