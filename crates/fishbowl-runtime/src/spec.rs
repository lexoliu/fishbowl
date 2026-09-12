use std::{collections::BTreeMap, fmt, num::NonZeroU32, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    budget::{Reservation, Sandbox},
    error::RuntimeError,
};

/// Guest architecture a container runs as.
///
/// On Apple Silicon the VM kernel is always arm64; [`Arch::Amd64`] selects an amd64
/// root filesystem whose userspace is translated by Rosetta, which is why
/// [`ContainerSpec::rosetta`] is only meaningful together with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    /// Native 64-bit ARM.
    Arm64,
    /// 64-bit x86, translated by Rosetta.
    Amd64,
}

impl Arch {
    /// The spelling `container` expects for `--arch`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::Amd64 => "amd64",
        }
    }

    /// The architecture the host runs natively, and so the one a sandbox runs without
    /// translation.
    pub const HOST: Self = if cfg!(target_arch = "aarch64") {
        Self::Arm64
    } else {
        Self::Amd64
    };

    /// Whether running this architecture requires Rosetta translation on Apple Silicon.
    #[must_use]
    pub const fn needs_rosetta(self) -> bool {
        matches!(self, Self::Amd64)
    }
}

impl std::str::FromStr for Arch {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "arm64" | "aarch64" => Ok(Self::Arm64),
            "amd64" | "x86_64" => Ok(Self::Amd64),
            _ => Err(RuntimeError::InvalidValue {
                kind: "architecture",
                value: value.to_owned(),
                reason: "expected `arm64` or `amd64`",
            }),
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// Number of virtual CPUs allocated to a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Cpus(NonZeroU32);

impl Cpus {
    /// Builds a CPU count.
    #[must_use]
    pub const fn new(count: NonZeroU32) -> Self {
        Self(count)
    }

    /// The underlying count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for Cpus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Memory allocated to a container, at the runtime's 1 MiB granularity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Memory {
    mebibytes: NonZeroU32,
}

impl Memory {
    /// Builds a memory size from mebibytes.
    #[must_use]
    pub const fn from_mib(mebibytes: NonZeroU32) -> Self {
        Self { mebibytes }
    }

    /// The size in mebibytes.
    #[must_use]
    pub const fn as_mib(self) -> u32 {
        self.mebibytes.get()
    }
}

impl fmt::Display for Memory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}M", self.mebibytes)
    }
}

/// A Linux capability the sandbox explicitly grants or removes.
///
/// Only the capabilities fishbowl reasons about are modelled. Anything outside this
/// set is left at the runtime default rather than being spelled out as a free string,
/// so a typo cannot silently widen the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Reconfigure networking, including the packet filter. Dropping this from the
    /// bounding set is what makes the egress policy tamper-proof from inside.
    NetAdmin,
    /// Open raw and packet sockets.
    NetRaw,
    /// Bind to privileged ports.
    NetBindService,
    /// Trace arbitrary processes; required by the debuggers in the analysis toolchain.
    SysPtrace,
    /// Load and unload kernel modules.
    SysModule,
    /// Broad administrative override, including mount.
    SysAdmin,
}

impl Capability {
    /// The spelling `container` expects for `--cap-add` and `--cap-drop`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetAdmin => "CAP_NET_ADMIN",
            Self::NetRaw => "CAP_NET_RAW",
            Self::NetBindService => "CAP_NET_BIND_SERVICE",
            Self::SysPtrace => "CAP_SYS_PTRACE",
            Self::SysModule => "CAP_SYS_MODULE",
            Self::SysAdmin => "CAP_SYS_ADMIN",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Name identifying a container to the runtime.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContainerName(String);

impl TryFrom<String> for ContainerName {
    type Error = RuntimeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ContainerName> for String {
    fn from(name: ContainerName) -> Self {
        name.0
    }
}

impl ContainerName {
    /// Validates and wraps a container name.
    ///
    /// # Errors
    /// Rejects empty names and any name containing characters outside
    /// `[A-Za-z0-9._-]`, which the runtime would refuse or mis-handle.
    pub fn new(name: impl Into<String>) -> Result<Self, RuntimeError> {
        let name = name.into();
        let invalid = |reason| RuntimeError::InvalidValue {
            kind: "container name",
            value: name.clone(),
            reason,
        };
        if name.is_empty() {
            return Err(invalid("names must not be empty"));
        }
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(invalid(
                "names may only contain letters, digits, `.`, `_` and `-`",
            ));
        }
        Ok(Self(name))
    }

    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContainerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reference to an OCI image, such as `docker.io/kalilinux/kali-rolling:latest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageReference(String);

impl TryFrom<String> for ImageReference {
    type Error = RuntimeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ImageReference> for String {
    fn from(reference: ImageReference) -> Self {
        reference.0
    }
}

impl ImageReference {
    /// Validates and wraps an image reference.
    ///
    /// # Errors
    /// Rejects empty references and references containing whitespace.
    pub fn new(reference: impl Into<String>) -> Result<Self, RuntimeError> {
        let reference = reference.into();
        if reference.is_empty() || reference.chars().any(char::is_whitespace) {
            return Err(RuntimeError::InvalidValue {
                kind: "image reference",
                value: reference,
                reason: "references must be non-empty and contain no whitespace",
            });
        }
        Ok(Self(reference))
    }

    /// The reference as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ImageReference {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A host directory made visible inside the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// Path on the macOS host.
    pub source: PathBuf,
    /// Path inside the container.
    pub target: PathBuf,
    /// Whether the guest sees the mount as read-only.
    pub readonly: bool,
}

impl Mount {
    /// A writable mount.
    #[must_use]
    pub fn writable(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            readonly: false,
        }
    }

    /// A read-only mount.
    #[must_use]
    pub fn read_only(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            readonly: true,
        }
    }

    fn render(&self) -> String {
        let mut spec = format!(
            "type=virtiofs,source={},target={}",
            self.source.display(),
            self.target.display()
        );
        if self.readonly {
            spec.push_str(",readonly");
        }
        spec
    }
}

/// A host-side unix socket exposed inside the container.
///
/// This is the channel the agent control plane uses: the host serves on [`Self::host`]
/// and the guest connects at [`Self::guest`], so no credential ever needs to traverse
/// the container's own network stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedSocket {
    /// Socket path on the macOS host.
    pub host: PathBuf,
    /// Socket path inside the container.
    pub guest: PathBuf,
}

/// The identity a container's init process runs as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSpec {
    /// User name or uid.
    pub user: String,
    /// Optional group name or gid.
    pub group: Option<String>,
}

impl UserSpec {
    /// A user with no explicit group.
    #[must_use]
    pub fn user(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            group: None,
        }
    }

    fn render(&self) -> String {
        match &self.group {
            Some(group) => format!("{}:{}", self.user, group),
            None => self.user.clone(),
        }
    }
}

/// Everything needed to start one sandbox container.
#[derive(Debug, Clone)]
pub struct ContainerSpec {
    /// Name the runtime will register the container under.
    pub name: ContainerName,
    /// Image to run.
    pub image: ImageReference,
    /// Guest architecture.
    pub arch: Arch,
    /// Sizing the host was measured against and found able to carry.
    pub reservation: Reservation<Sandbox>,
    /// Identity of the init process.
    pub user: Option<UserSpec>,
    /// Capabilities added on top of the runtime default set.
    pub cap_add: Vec<Capability>,
    /// Capabilities removed from the bounding set.
    pub cap_drop: Vec<Capability>,
    /// Host directories exposed to the guest.
    pub mounts: Vec<Mount>,
    /// Host unix sockets exposed to the guest.
    pub published_sockets: Vec<PublishedSocket>,
    /// Guest TCP ports published back to the host, as `host_port:guest_port`.
    pub published_ports: Vec<(u16, u16)>,
    /// Environment for the init process.
    pub env: BTreeMap<String, String>,
    /// Entrypoint override.
    pub entrypoint: Option<PathBuf>,
    /// Arguments passed to the init process.
    pub arguments: Vec<String>,
    /// Whether the runtime supervises an init process that reaps children.
    pub init: bool,
    /// Whether the container's root filesystem is read-only.
    pub read_only: bool,
    /// Paths hidden inside the guest, in addition to the runtime defaults.
    pub masked_paths: Vec<PathBuf>,
}

impl ContainerSpec {
    /// A spec with the runtime defaults for everything but name, image and sizing.
    #[must_use]
    pub fn new(
        name: ContainerName,
        image: ImageReference,
        arch: Arch,
        reservation: Reservation<Sandbox>,
    ) -> Self {
        Self {
            name,
            image,
            arch,
            reservation,
            user: None,
            cap_add: Vec::new(),
            cap_drop: Vec::new(),
            mounts: Vec::new(),
            published_sockets: Vec::new(),
            published_ports: Vec::new(),
            env: BTreeMap::new(),
            entrypoint: None,
            arguments: Vec::new(),
            init: false,
            read_only: false,
            masked_paths: Vec::new(),
        }
    }

    /// Renders the argument vector for `container run --detach`.
    pub(crate) fn render_run_arguments(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            self.name.to_string(),
            "--arch".to_owned(),
            self.arch.as_str().to_owned(),
            "--cpus".to_owned(),
            self.reservation.cpus().to_string(),
            "--memory".to_owned(),
            self.reservation.memory().to_string(),
        ];
        if self.arch.needs_rosetta() {
            args.push("--rosetta".to_owned());
        }
        if self.init {
            args.push("--init".to_owned());
        }
        if self.read_only {
            args.push("--read-only".to_owned());
        }
        if let Some(user) = &self.user {
            args.push("--user".to_owned());
            args.push(user.render());
        }
        for capability in &self.cap_add {
            args.push("--cap-add".to_owned());
            args.push(capability.as_str().to_owned());
        }
        for capability in &self.cap_drop {
            args.push("--cap-drop".to_owned());
            args.push(capability.as_str().to_owned());
        }
        for mount in &self.mounts {
            args.push("--mount".to_owned());
            args.push(mount.render());
        }
        for socket in &self.published_sockets {
            args.push("--publish-socket".to_owned());
            args.push(format!(
                "{}:{}",
                socket.host.display(),
                socket.guest.display()
            ));
        }
        for (host_port, guest_port) in &self.published_ports {
            args.push("--publish".to_owned());
            args.push(format!("{host_port}:{guest_port}"));
        }
        for path in &self.masked_paths {
            args.push("--masked-path".to_owned());
            args.push(path.display().to_string());
        }
        for (key, value) in &self.env {
            args.push("--env".to_owned());
            args.push(format!("{key}={value}"));
        }
        if let Some(entrypoint) = &self.entrypoint {
            args.push("--entrypoint".to_owned());
            args.push(entrypoint.display().to_string());
        }
        args.push(self.image.to_string());
        args.extend(self.arguments.iter().cloned());
        args
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ContainerSpec {
        ContainerSpec::new(
            ContainerName::new("fishbowl-demo").unwrap(),
            ImageReference::new("localhost/fishbowl:latest").unwrap(),
            Arch::Arm64,
            Reservation::for_tests(
                Cpus::new(NonZeroU32::new(4).unwrap()),
                Memory::from_mib(NonZeroU32::new(8192).unwrap()),
            ),
        )
    }

    #[test]
    fn container_names_reject_shell_metacharacters() {
        assert!(ContainerName::new("sandbox; rm -rf /").is_err());
        assert!(ContainerName::new("").is_err());
        assert!(ContainerName::new("fishbowl.1_a").is_ok());
    }

    #[test]
    fn amd64_specs_always_request_rosetta() {
        let mut spec = spec();
        spec.arch = Arch::Amd64;
        let args = spec.render_run_arguments();
        assert!(args.contains(&"--rosetta".to_owned()));
    }

    #[test]
    fn arm64_specs_never_request_rosetta() {
        let args = spec().render_run_arguments();
        assert!(!args.contains(&"--rosetta".to_owned()));
    }

    #[test]
    fn dropped_capabilities_are_rendered_with_their_cap_prefix() {
        let mut spec = spec();
        spec.cap_drop = vec![Capability::NetAdmin];
        let args = spec.render_run_arguments();
        let index = args.iter().position(|a| a == "--cap-drop").unwrap();
        assert_eq!(args[index + 1], "CAP_NET_ADMIN");
    }

    #[test]
    fn read_only_mounts_carry_the_readonly_option() {
        let mount = Mount::read_only("/host/samples", "/samples");
        assert_eq!(
            mount.render(),
            "type=virtiofs,source=/host/samples,target=/samples,readonly"
        );
    }

    #[test]
    fn image_arguments_come_last() {
        let mut spec = spec();
        spec.arguments = vec!["sleep".to_owned(), "infinity".to_owned()];
        let args = spec.render_run_arguments();
        let image = args
            .iter()
            .position(|a| a == "localhost/fishbowl:latest")
            .unwrap();
        assert_eq!(&args[image + 1..], ["sleep", "infinity"]);
    }
}
