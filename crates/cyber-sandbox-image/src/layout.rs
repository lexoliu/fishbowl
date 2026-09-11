use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A unix account the image creates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Account name.
    pub name: String,
    /// Numeric user id.
    pub uid: u32,
    /// Numeric group id.
    pub gid: u32,
}

/// The fixed facts a sandbox image, its egress policy and the host CLI must all agree on.
///
/// Ports, uids and paths appear in the packet filter, in the gateway's own listeners and
/// in the host's audit reader. Holding them in one value that every renderer reads from
/// is what keeps them from drifting apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxLayout {
    /// Account the researcher's own shell and the agents run as.
    pub researcher: Account,
    /// Account sample code is detonated under, which owns nothing worth taking.
    pub detonate: Account,
    /// Account that runs the audit gateway.
    pub gateway: Account,
    /// Loopback port the transparent TCP proxy listens on.
    pub proxy_port: u16,
    /// Loopback port the intercepting DNS resolver listens on.
    pub dns_port: u16,
    /// Port sshd listens on inside the sandbox.
    pub ssh_port: u16,
    /// NFLOG group the packet filter reports refused traffic on.
    pub nflog_group: u16,
    /// Directory the gateway writes its audit trail into.
    pub audit_directory: PathBuf,
    /// Home directory of the gateway account, holding its generated CA.
    pub gateway_home: PathBuf,
    /// Authorized keys file for the researcher account.
    pub authorized_keys: PathBuf,
    /// Read-only mount point holding samples under analysis.
    pub samples_dir: PathBuf,
    /// Writable working directory for the researcher account.
    pub work_dir: PathBuf,
    /// Directory the host's per-attachment sockets and credential files live in.
    pub runtime_dir: PathBuf,
    /// Host variable holding the researcher's `Auth-Key` for `MalwareBazaar`, handed to the
    /// researcher account's environment in the session whenever the host has it set.
    pub malwarebazaar_key: String,
}

impl Default for SandboxLayout {
    fn default() -> Self {
        Self {
            // Both ids sit in 65000-65533, the band Debian policy reserves and never
            // allocates dynamically, so a base image cannot already hold an account
            // that collides with them. The gateway's id in particular is load-bearing:
            // the packet filter tells its traffic apart from the researcher's by uid
            // alone, so it has to be a constant the image and the policy agree on.
            researcher: Account {
                name: "researcher".to_owned(),
                uid: 65002,
                gid: 65002,
            },
            gateway: Account {
                name: "gateway".to_owned(),
                uid: 65001,
                gid: 65001,
            },
            // A sample and the token an agent was lent are the two things in this machine
            // that must not share a uid: the credential file is the researcher's at 0600,
            // and everything a sample could read of it is on the other side of that.
            detonate: Account {
                name: "detonate".to_owned(),
                uid: 65003,
                gid: 65003,
            },
            proxy_port: 15000,
            dns_port: 15353,
            ssh_port: 22,
            nflog_group: 1,
            audit_directory: PathBuf::from("/var/log/cyber-sandbox"),
            gateway_home: PathBuf::from("/var/lib/cyber-sandbox"),
            authorized_keys: PathBuf::from("/etc/ssh/authorized_keys.d/researcher"),
            samples_dir: PathBuf::from("/samples"),
            work_dir: PathBuf::from("/work"),
            // Reachable by the researcher account alone: everything written here is
            // written for one process and read by it, and the courier takes the
            // credential it wrote back off the disk when the agent it served exits.
            runtime_dir: PathBuf::from("/run/cyber-sandbox"),
            // The name OpenCTI's connector reads, and the product's own; there is no
            // convention beyond that, and one abuse.ch key serves all of their services.
            malwarebazaar_key: "MALWAREBAZAAR_API_KEY".to_owned(),
        }
    }
}

/// File name of the JSONL audit trail inside [`SandboxLayout::audit_directory`].
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";

/// File name of the gateway's MITM certificate authority inside its home directory.
pub const CA_FILE_NAME: &str = "gateway-ca.crt";

impl SandboxLayout {
    /// Full path of the audit trail inside the sandbox.
    #[must_use]
    pub fn audit_trail(&self) -> PathBuf {
        self.audit_directory.join(AUDIT_FILE_NAME)
    }

    /// Full path of the gateway's CA certificate inside the sandbox.
    #[must_use]
    pub fn ca_certificate(&self) -> PathBuf {
        self.gateway_home.join(CA_FILE_NAME)
    }

    /// Directory the audit trail lives in.
    #[must_use]
    pub fn audit_directory(&self) -> &Path {
        &self.audit_directory
    }

    /// Home directory of the researcher account.
    #[must_use]
    pub fn researcher_home(&self) -> PathBuf {
        PathBuf::from(format!("/home/{}", self.researcher.name))
    }

    /// Where Devin reads the credentials file the courier lends it.
    ///
    /// The path is Devin's own — it reads exactly here and nowhere else — so the loan is
    /// delivered where the agent already looks rather than where it could be pointed.
    #[must_use]
    pub fn devin_credentials(&self) -> PathBuf {
        self.researcher_home()
            .join(".local/share/devin/credentials.toml")
    }
}
