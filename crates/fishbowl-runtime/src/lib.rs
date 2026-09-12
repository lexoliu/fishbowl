//! A typed driver for [`apple/container`](https://github.com/apple/container).
//!
//! `container` is a CLI, so this crate's job is to make the CLI surface unavailable to
//! callers and expose a checked one instead: a [`ContainerSpec`] cannot express an
//! invalid architecture, an unparsable memory size, or a capability name the runtime
//! would reject, and every invocation that exits non-zero becomes a [`RuntimeError`]
//! carrying the runtime's own stderr rather than a silent fallback.

mod apple;
mod budget;
mod error;
mod inspect;
mod spec;

pub use apple::{AppleContainer, ExecOutput, ExecStream, ImageBuild};
pub use budget::{Build, Committed, HostBudget, Reservation, Sandbox, Workload};
pub use error::RuntimeError;
pub use inspect::{
    ContainerState, ImageDescription, NetworkStatus, Resources, RunState, SystemStatus,
};
pub use spec::{
    Arch, Capability, ContainerName, ContainerSpec, Cpus, ImageReference, Memory, Mount,
    PublishedSocket, UserSpec,
};
