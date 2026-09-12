use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use serde::Deserialize;

use crate::{
    budget::{Reservation, Workload},
    error::RuntimeError,
    spec::{Arch, ContainerName, Cpus, ImageReference, Memory},
};

/// Health of the `container` system services.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemStatus {
    /// Whether the API server is running.
    pub status: String,
    /// Version banner reported by the API server.
    pub api_server_version: String,
    /// Directory holding runtime state, kernels and images.
    pub app_root: String,
}

impl SystemStatus {
    /// Whether the API server is up and able to serve requests.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.status == "running"
    }
}

/// Lifecycle state of a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunState {
    /// The container is running.
    Running,
    /// The container exists but is not running.
    Stopped,
    /// The container is starting up.
    Starting,
    /// The container is shutting down.
    Stopping,
}

/// The subset of `container inspect` this crate depends on.
#[derive(Debug, Clone, Deserialize)]
pub struct ContainerState {
    /// Name the container is registered under.
    pub id: ContainerName,
    /// Runtime configuration the container was created with.
    pub configuration: Configuration,
    /// Live status of the container.
    pub status: Status,
}

impl ContainerState {
    /// The container's IPv4 address on its first attached network.
    ///
    /// Returns `None` before the guest has finished configuring its interfaces.
    #[must_use]
    pub fn ipv4_address(&self) -> Option<Ipv4Addr> {
        self.status.networks.first()?.ipv4_address()
    }

    /// The gateway the container routes through, which is also the macOS host.
    #[must_use]
    pub fn ipv4_gateway(&self) -> Option<Ipv4Addr> {
        self.status.networks.first()?.ipv4_gateway
    }
}

/// Creation-time configuration of a container.
#[derive(Debug, Clone, Deserialize)]
pub struct Configuration {
    /// Image the container was created from.
    pub image: ImageDescription,
    /// Guest platform.
    pub platform: Platform,
    /// Whether Rosetta translation is enabled.
    pub rosetta: bool,
    /// Sizing the container was created with.
    pub resources: Resources,
}

/// The image a container was created from.
#[derive(Debug, Clone, Deserialize)]
pub struct ImageDescription {
    /// Reference the image was built or pulled under.
    pub reference: ImageReference,
}

/// Sizing a container was created with.
///
/// A VM's allocation is fixed at creation, so this is how a container that already exists
/// is checked against the budget it should have been created under.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    /// Virtual CPUs allocated.
    pub cpus: u32,
    /// Memory allocated, in bytes.
    pub memory_in_bytes: u64,
}

impl Resources {
    /// Whether this allocation is exactly what `reservation` asks for.
    #[must_use]
    pub fn matches<W: Workload>(&self, reservation: &Reservation<W>) -> bool {
        self.cpus == reservation.cpus().get()
            && self.memory_in_bytes == u64::from(reservation.memory().as_mib()) * MEBIBYTE
    }

    /// The allocation expressed in the dimensions a reservation is made in.
    ///
    /// A machine's size is fixed when it is created, so a container that already exists
    /// has to ask the host for the allocation it already has rather than a freshly
    /// suggested one.
    ///
    /// # Errors
    /// Fails when the runtime reports an allocation no machine can have: no vCPU at all,
    /// or a memory size that is not a whole number of mebibytes.
    pub fn allocation(&self) -> Result<(Cpus, Memory), RuntimeError> {
        let cpus = NonZeroU32::new(self.cpus).ok_or_else(|| RuntimeError::InvalidValue {
            kind: "container allocation",
            value: format!("{} vCPUs", self.cpus),
            reason: "a machine runs on at least one",
        })?;
        let mebibytes = u32::try_from(self.memory_in_bytes / MEBIBYTE)
            .ok()
            .filter(|_| self.memory_in_bytes.is_multiple_of(MEBIBYTE))
            .and_then(NonZeroU32::new)
            .ok_or_else(|| RuntimeError::InvalidValue {
                kind: "container allocation",
                value: format!("{} bytes of memory", self.memory_in_bytes),
                reason: "memory is allocated in whole mebibytes",
            })?;
        Ok((Cpus::new(cpus), Memory::from_mib(mebibytes)))
    }
}

/// Bytes in a mebibyte, the granularity the runtime reports memory at.
const MEBIBYTE: u64 = 1024 * 1024;

/// Guest platform of a container.
#[derive(Debug, Clone, Deserialize)]
pub struct Platform {
    /// Guest architecture.
    pub architecture: Arch,
    /// Guest operating system.
    pub os: String,
}

/// Live status of a container.
#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    /// Lifecycle state.
    pub state: RunState,
    /// Attached networks and their assigned addresses.
    #[serde(default)]
    pub networks: Vec<NetworkStatus>,
}

/// One attached network and the addresses assigned on it.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    /// Name of the network.
    pub network: String,
    /// Guest hostname on this network.
    pub hostname: String,
    /// Assigned IPv4 address in CIDR form.
    pub ipv4_address: String,
    /// Gateway for the IPv4 subnet.
    pub ipv4_gateway: Option<Ipv4Addr>,
    /// Assigned IPv6 address in CIDR form, when the network has IPv6.
    pub ipv6_address: Option<String>,
}

impl NetworkStatus {
    /// The IPv4 address with its prefix length stripped.
    #[must_use]
    pub fn ipv4_address(&self) -> Option<Ipv4Addr> {
        self.ipv4_address
            .split('/')
            .next()
            .and_then(|address| address.parse().ok())
    }

    /// The IPv6 address with its prefix length stripped.
    #[must_use]
    pub fn ipv6_address(&self) -> Option<Ipv6Addr> {
        self.ipv6_address
            .as_deref()?
            .split('/')
            .next()
            .and_then(|address| address.parse().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSPECT: &str = include_str!("../tests/data/inspect.json");
    const SYSTEM_STATUS: &str = include_str!("../tests/data/system-status.json");

    #[test]
    fn inspect_output_yields_the_guest_address_and_gateway() {
        let states: Vec<ContainerState> = serde_json::from_str(INSPECT).unwrap();
        let state = states.first().unwrap();
        assert_eq!(state.id.as_str(), "cs-probe");
        assert_eq!(state.status.state, RunState::Running);
        assert_eq!(state.configuration.platform.architecture, Arch::Arm64);
        assert!(!state.configuration.rosetta);
        assert_eq!(
            state.ipv4_address(),
            Some(Ipv4Addr::new(192, 168, 64, 2)),
            "the guest address must survive CIDR stripping"
        );
        assert_eq!(state.ipv4_gateway(), Some(Ipv4Addr::new(192, 168, 64, 1)));
    }

    #[test]
    fn system_status_reports_running() {
        let status: SystemStatus = serde_json::from_str(SYSTEM_STATUS).unwrap();
        assert!(status.is_running());
    }
}
