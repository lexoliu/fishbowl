//! The host resource budget every VM allocation has to pass through.
//!
//! `container` grants whatever it is asked for: `--memory 8192M` is honoured even when
//! macOS has nothing left to give, and a build grows the builder's snapshot store until
//! the volume holding it is full. On 2026-09-03 that combination took this host down — a
//! full data volume stops macOS growing a swapfile, so guest writes and host paging ended
//! up fighting over the same exhausted disk, and the machine wedged.
//!
//! Sizing is therefore not a free parameter. [`HostBudget::measure`] reads what the
//! machine actually has, and the only way to obtain a [`Reservation`] — which is what
//! `ContainerSpec::new` and `AppleContainer::build` accept, rather than a bare CPU count
//! and memory size — is to pass the budget's checks. The [`Workload`] marker keeps the two
//! kinds apart at compile time: a build needs far more free disk than a sandbox does, and
//! a reservation taken for one cannot be spent on the other.
//!
//! The host is measured against what is *already running*, not against an empty machine:
//! [`HostBudget::measure`] takes the [`Committed`] holdings of the runtime's live virtual
//! machines, so two allocations that each fit on their own can no longer oversubscribe the
//! host between them.

use std::{collections::BTreeMap, marker::PhantomData, num::NonZeroU32, path::Path};

use sysinfo::{Disks, MemoryRefreshKind, RefreshKind, System};

use crate::{
    error::RuntimeError,
    inspect::{ContainerState, Resources, RunState},
    spec::{ContainerName, Cpus, Memory},
};

/// Bytes in a mebibyte.
const MIB: u64 = 1024 * 1024;

/// Bytes in a gibibyte.
const GIB: u64 = 1024 * MIB;

/// Memory that stays with macOS no matter what a guest asks for.
///
/// The host runs the agents, the editor and the compiler toolchain while a sandbox is up,
/// and this box has only 6 GiB of swap to absorb a bad estimate.
const HOST_MEMORY_RESERVE_MIB: u32 = 8192;

/// Cores that stay with macOS, for the same reason.
const HOST_CPU_RESERVE: u32 = 2;

/// Fraction of the remaining allowance a workload is given when the caller does not size
/// it explicitly: enough to work with, and small enough that a second sandbox still fits.
const SUGGESTED_DIVISOR: u32 = 2;

/// A kind of virtual machine the runtime is asked to start, and what the host must have
/// spare before it may be started.
pub trait Workload: Copy {
    /// How the workload is named in budget errors.
    const NAME: &'static str;

    /// Free space that must remain on the volume holding the runtime's state.
    ///
    /// A build's working set is unbounded — `BuildKit` keeps every layer snapshot of every
    /// stage — so its floor is the one that matters. A sandbox only grows by what the
    /// researcher writes inside it.
    const DISK_FLOOR: u64;

    /// The singleton virtual machine a reservation for this workload takes the place of,
    /// when there is one.
    ///
    /// Whatever that machine currently holds is about to be released, so it must not count
    /// against the reservation that replaces it — otherwise every build would size the
    /// builder against the builder it is recreating and ratchet it smaller each time.
    const REPLACES: Option<&'static str>;
}

/// A sandbox VM running untrusted samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sandbox;

impl Workload for Sandbox {
    const NAME: &'static str = "a sandbox";
    const DISK_FLOOR: u64 = 20 * GIB;
    // Every sandbox is a new container: `up` refuses an id the runtime already holds, so
    // a reservation for one never displaces anything.
    const REPLACES: Option<&'static str> = None;
}

/// The shared image builder VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Build;

impl Workload for Build {
    const NAME: &'static str = "an image build";
    const DISK_FLOOR: u64 = 60 * GIB;
    const REPLACES: Option<&'static str> = Some(crate::apple::BUILDER);
}

/// What one live virtual machine holds of the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Holding {
    cpus: u32,
    memory_mib: u32,
}

impl Holding {
    /// What the runtime says a container was created with, in the budget's own units.
    fn of(resources: &Resources) -> Self {
        Self {
            cpus: resources.cpus,
            memory_mib: u32::try_from(resources.memory_in_bytes / MIB).unwrap_or(u32::MAX),
        }
    }

    fn plus(self, other: Self) -> Self {
        Self {
            cpus: self.cpus.saturating_add(other.cpus),
            memory_mib: self.memory_mib.saturating_add(other.memory_mib),
        }
    }
}

/// The cores and memory the runtime's live virtual machines already hold.
///
/// Kept per machine rather than as a single total, because a reservation that replaces a
/// named machine ([`Workload::REPLACES`]) must not be charged for what that machine holds
/// today.
#[derive(Debug, Clone, Default)]
pub struct Committed {
    machines: BTreeMap<String, Holding>,
}

impl Committed {
    /// The holdings of every container in `states` that is running or on its way up.
    ///
    /// A stopped container holds nothing: its allocation is fixed at creation, but the VM
    /// it belongs to is not resident.
    #[must_use]
    pub fn of<'a>(states: impl IntoIterator<Item = &'a ContainerState>) -> Self {
        let mut committed = Self::default();
        for state in states {
            if matches!(state.status.state, RunState::Running | RunState::Starting) {
                committed.insert(&state.id, Holding::of(&state.configuration.resources));
            }
        }
        committed
    }

    fn insert(&mut self, name: &ContainerName, holding: Holding) {
        self.machines.insert(name.as_str().to_owned(), holding);
    }

    /// Everything held except by the machine a reservation for `W` replaces.
    fn total<W: Workload>(&self) -> Holding {
        self.machines
            .iter()
            .filter(|(name, _)| W::REPLACES != Some(name.as_str()))
            .fold(Holding::default(), |total, (_, holding)| {
                total.plus(*holding)
            })
    }

    /// How the holdings read in a budget error.
    fn describe<W: Workload>(&self) -> String {
        let total = self.total::<W>();
        format!(
            "{} live machines already hold {} cores and {} MiB",
            self.machines.len(),
            total.cpus,
            total.memory_mib
        )
    }
}

/// An allocation the host has been measured against and found able to carry.
///
/// Cannot be constructed directly: [`HostBudget::reserve`] is the only source, so a spec
/// that exists has already been checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reservation<W: Workload> {
    cpus: Cpus,
    memory: Memory,
    workload: PhantomData<W>,
}

impl<W: Workload> Reservation<W> {
    /// Virtual CPUs the workload may use.
    #[must_use]
    pub const fn cpus(&self) -> Cpus {
        self.cpus
    }

    /// Memory the workload may use.
    #[must_use]
    pub const fn memory(&self) -> Memory {
        self.memory
    }

    /// A reservation for the crate's own tests, which must build specs without a host to
    /// measure. Never available outside `cfg(test)`, so production code cannot skip the
    /// budget by reaching for it.
    #[cfg(test)]
    pub(crate) const fn for_tests(cpus: Cpus, memory: Memory) -> Self {
        Self {
            cpus,
            memory,
            workload: PhantomData,
        }
    }
}

/// What the host has to offer, measured once per invocation.
#[derive(Debug, Clone)]
pub struct HostBudget {
    cpus: u32,
    memory_mib: u32,
    free_disk: u64,
    committed: Committed,
}

impl HostBudget {
    /// Measures the host, counting free space on the volume that holds `state` and
    /// charging `committed` against what the machine has.
    ///
    /// `state` is the runtime's own state directory rather than a fixed mount point,
    /// because the volume that fills up is whichever one holds the images and VM disks.
    /// `committed` is what the runtime's live virtual machines already hold, so that a
    /// second allocation is measured against the host as it is, not as it was before the
    /// first one started.
    ///
    /// # Errors
    /// Fails when the core count, the installed memory or the free space of the volume
    /// holding `state` cannot be determined.
    pub fn measure(state: &Path, committed: Committed) -> Result<Self, RuntimeError> {
        let cpus = std::thread::available_parallelism()
            .map_err(|source| RuntimeError::Probe {
                what: "core count",
                reason: source.to_string(),
            })?
            .get();
        let cpus = u32::try_from(cpus).map_err(|_| RuntimeError::Probe {
            what: "core count",
            reason: format!("{cpus} cores does not fit in a u32"),
        })?;

        let system = System::new_with_specifics(
            RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        let memory_mib = system.total_memory() / MIB;
        let memory_mib = u32::try_from(memory_mib).map_err(|_| RuntimeError::Probe {
            what: "installed memory",
            reason: format!("{memory_mib} MiB does not fit in a u32"),
        })?;
        if memory_mib == 0 {
            return Err(RuntimeError::Probe {
                what: "installed memory",
                reason: "the system reports no memory at all".to_owned(),
            });
        }

        let free_disk = free_space(state)?;
        Ok(Self {
            cpus,
            memory_mib,
            free_disk,
            committed,
        })
    }

    /// Free space left on the volume holding the runtime's state.
    #[must_use]
    pub const fn free_disk(&self) -> u64 {
        self.free_disk
    }

    /// Cores a workload of kind `W` may still be given.
    fn spare_cpus<W: Workload>(&self) -> u32 {
        self.cpus
            .saturating_sub(HOST_CPU_RESERVE)
            .saturating_sub(self.committed.total::<W>().cpus)
    }

    /// Memory a workload of kind `W` may still be given, in mebibytes.
    fn spare_memory_mib<W: Workload>(&self) -> u32 {
        self.memory_mib
            .saturating_sub(HOST_MEMORY_RESERVE_MIB)
            .saturating_sub(self.committed.total::<W>().memory_mib)
    }

    /// Checks an explicit allocation against the host.
    ///
    /// # Errors
    /// Returns [`RuntimeError::Budget`] when the host is short of free disk, cores or
    /// memory for `W`, naming what was asked for and what is actually available.
    pub fn reserve<W: Workload>(
        &self,
        cpus: Cpus,
        memory: Memory,
    ) -> Result<Reservation<W>, RuntimeError> {
        if self.free_disk < W::DISK_FLOOR {
            return Err(RuntimeError::Budget {
                workload: W::NAME,
                needed: format!("{} GiB of free disk", W::DISK_FLOOR / GIB),
                available: format!("only {} MiB is free", self.free_disk / MIB),
            });
        }
        if cpus.get() > self.spare_cpus::<W>() {
            return Err(RuntimeError::Budget {
                workload: W::NAME,
                needed: format!("{cpus} vCPUs"),
                available: format!(
                    "the host's {} cores leave {} once macOS keeps {HOST_CPU_RESERVE} and {}",
                    self.cpus,
                    self.spare_cpus::<W>(),
                    self.committed.describe::<W>()
                ),
            });
        }
        if memory.as_mib() > self.spare_memory_mib::<W>() {
            return Err(RuntimeError::Budget {
                workload: W::NAME,
                needed: format!("{} MiB of memory", memory.as_mib()),
                available: format!(
                    "the host's {} MiB leave {} MiB once macOS keeps {HOST_MEMORY_RESERVE_MIB} MiB and {}",
                    self.memory_mib,
                    self.spare_memory_mib::<W>(),
                    self.committed.describe::<W>()
                ),
            });
        }
        Ok(Reservation {
            cpus,
            memory,
            workload: PhantomData,
        })
    }

    /// The allocation a workload gets when the caller does not size it: half of what the
    /// host can still spare, so that a second one fits alongside it.
    ///
    /// # Errors
    /// Returns [`RuntimeError::Budget`] when the host cannot spare even that.
    pub fn suggest<W: Workload>(&self) -> Result<Reservation<W>, RuntimeError> {
        let cpus = self.spare_cpus::<W>().div_euclid(SUGGESTED_DIVISOR);
        let memory = self.spare_memory_mib::<W>().div_euclid(SUGGESTED_DIVISOR);
        let (Some(cpus), Some(memory)) = (NonZeroU32::new(cpus), NonZeroU32::new(memory)) else {
            return Err(RuntimeError::Budget {
                workload: W::NAME,
                needed: "a share of the host's cores and memory".to_owned(),
                available: format!(
                    "the host's {} cores and {} MiB leave nothing once macOS is kept whole and {}",
                    self.cpus,
                    self.memory_mib,
                    self.committed.describe::<W>()
                ),
            });
        };
        self.reserve(Cpus::new(cpus), Memory::from_mib(memory))
    }
}

/// Free space on the mounted volume containing `path`.
fn free_space(path: &Path) -> Result<u64, RuntimeError> {
    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
        .map(sysinfo::Disk::available_space)
        .ok_or_else(|| RuntimeError::Probe {
            what: "free disk space",
            reason: format!("no mounted volume contains {}", path.display()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(cpus: u32, memory_mib: u32, free_gib: u64) -> HostBudget {
        HostBudget {
            cpus,
            memory_mib,
            free_disk: free_gib * GIB,
            committed: Committed::default(),
        }
    }

    fn running(host: HostBudget, name: &str, cpus: u32, memory_mib: u32) -> HostBudget {
        let mut host = host;
        host.committed.insert(
            &ContainerName::new(name).unwrap(),
            Holding { cpus, memory_mib },
        );
        host
    }

    fn size(mebibytes: u32) -> Memory {
        Memory::from_mib(NonZeroU32::new(mebibytes).unwrap())
    }

    fn count(cpus: u32) -> Cpus {
        Cpus::new(NonZeroU32::new(cpus).unwrap())
    }

    #[test]
    fn a_build_needs_far_more_free_disk_than_a_sandbox() {
        let host = budget(12, 32768, 30);
        assert!(
            host.reserve::<Sandbox>(count(4), size(8192)).is_ok(),
            "30 GiB free is enough for a sandbox"
        );
        assert!(
            host.reserve::<Build>(count(4), size(8192)).is_err(),
            "30 GiB free is not enough for a build: this is what wedged the host"
        );
    }

    #[test]
    fn nothing_starts_below_the_sandbox_disk_floor() {
        let host = budget(12, 32768, 5);
        assert!(host.reserve::<Sandbox>(count(1), size(1024)).is_err());
    }

    #[test]
    fn macos_keeps_its_share_of_memory_and_cores() {
        let host = budget(12, 32768, 200);
        assert!(
            host.reserve::<Sandbox>(count(11), size(8192)).is_err(),
            "11 of 12 cores leaves macOS one core"
        );
        assert!(
            host.reserve::<Sandbox>(count(4), size(32768)).is_err(),
            "all of the host's memory leaves macOS none"
        );
        assert!(
            host.reserve::<Sandbox>(count(10), size(24576)).is_ok(),
            "the reserve is a floor, not a margin on top of it"
        );
    }

    #[test]
    fn a_suggestion_is_half_of_what_the_host_can_spare() {
        let reservation = budget(12, 32768, 200).suggest::<Sandbox>().unwrap();
        assert_eq!(reservation.cpus().get(), 5);
        assert_eq!(reservation.memory().as_mib(), 12288);
    }

    #[test]
    fn a_host_with_nothing_to_spare_cannot_suggest_an_allocation() {
        assert!(budget(2, 8192, 200).suggest::<Sandbox>().is_err());
    }

    #[test]
    fn every_running_sandbox_is_charged_against_the_next_one() {
        // Before the budget counted what was already up, each of these passed on its own
        // and any number of them could be started: three suggested sandboxes would have
        // claimed 15 cores and 36 GiB of a 12-core, 32 GiB host.
        let mut host = budget(12, 32768, 200);
        let first = host.suggest::<Sandbox>().unwrap();
        assert_eq!((first.cpus().get(), first.memory().as_mib()), (5, 12288));

        host = running(host, "lab", first.cpus().get(), first.memory().as_mib());
        let second = host
            .reserve::<Sandbox>(count(5), size(12288))
            .expect("two suggested sandboxes fit exactly, which is what halving is for");

        host = running(
            host,
            "rosetta",
            second.cpus().get(),
            second.memory().as_mib(),
        );
        assert!(
            host.reserve::<Sandbox>(count(1), size(1024)).is_err(),
            "the host is now spoken for: a third sandbox would eat into what macOS keeps"
        );
        assert!(
            host.suggest::<Sandbox>().is_err(),
            "and there is no smaller share to suggest either"
        );
    }

    #[test]
    fn a_stopped_sandbox_holds_nothing() {
        let states: Vec<ContainerState> =
            serde_json::from_str(include_str!("../tests/data/inspect.json")).unwrap();
        let committed = Committed::of(&states);
        assert_eq!(
            committed.total::<Sandbox>(),
            Holding {
                cpus: 4,
                memory_mib: 1024
            },
            "only the running container counts"
        );
    }

    #[test]
    fn the_builder_is_not_charged_against_the_build_that_recreates_it() {
        let host = running(budget(12, 32768, 200), crate::apple::BUILDER, 5, 12288);
        let reservation = host.suggest::<Build>().unwrap();
        assert_eq!(
            (reservation.cpus().get(), reservation.memory().as_mib()),
            (5, 12288),
            "the builder's own hold is about to be released, so it must not shrink the \
             sizing that replaces it"
        );
        let sandbox = host.suggest::<Sandbox>().unwrap();
        assert_eq!(
            (sandbox.cpus().get(), sandbox.memory().as_mib()),
            (2, 6144),
            "a sandbox does not replace the builder, so it is charged for what the \
             builder holds while it runs"
        );
    }
}
