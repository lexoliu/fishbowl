//! The source build of OpenSSH an `x86_64` image has to carry.
//!
//! An amd64 sandbox is a whole `x86_64` root filesystem translated by Rosetta, and Rosetta
//! cannot install a seccomp filter: `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` returns
//! `EINVAL` in the translated guest, where the same call succeeds natively on arm64.
//! Kali's sshd is built with `--with-sandbox=seccomp_filter`, and OpenSSH treats a
//! sandbox it cannot enter as fatal — the preauth child dies with
//! `ssh_sandbox_child: prctl(PR_SET_SECCOMP): Invalid argument [preauth]` and every
//! connection is reset before key exchange finishes. The mechanism is chosen at configure
//! time and has no `sshd_config` keyword, so the only sshd that can serve a translated
//! guest is one compiled with a different one.
//!
//! Linux offers two mechanisms, and Rosetta breaks both. The other one, `rlimit`, confines
//! the preauth child by zeroing `RLIMIT_FSIZE` and `RLIMIT_NOFILE`; OpenSSH only enables
//! it when its configure probe can still `select()` afterwards, and under Rosetta that
//! probe fails — `configure: error: rlimit sandbox requires select to work with rlimit`,
//! observed on 2026-09-03 building 10.5p1 for amd64. So a translated sshd can only be
//! built with `--with-sandbox=no`.
//!
//! The amd64 image therefore builds a pinned OpenSSH release with that mechanism and
//! replaces the packaged binaries with it. What is given up is one layer of
//! defence-in-depth around the preauth child, not privilege separation itself: the child
//! still runs as an unprivileged, chrooted account. That layer is also the one this
//! design leans on least — the sandbox's boundary is the virtual machine, which is why
//! `CAP_NET_ADMIN` is dropped from the bounding set rather than merely from root, and an
//! attacker who could exploit sshd preauth from inside the guest already holds code
//! execution there.
//!
//! The arm64 image keeps Kali's package, whose seccomp sandbox works natively and is the
//! stronger of the two.

use fishbowl_runtime::Arch;

/// Upstream release the amd64 image builds its sshd from.
const VERSION: &str = "10.5p1";

/// Privilege-separation sandbox the build is configured with.
///
/// `no` is not a preference: `seccomp_filter` and `rlimit` are the only two Linux offers
/// and Rosetta supports neither, as the module documentation records.
const SANDBOX: &str = "no";

/// SHA-256 of `openssh-<VERSION>.tar.gz`, checked in the build before it is unpacked.
///
/// Confirmed identical on cdn.openbsd.org, ftp.openbsd.org and mirror.leaseweb.com on
/// 2026-09-03. The build fails rather than compiling a tarball that does not match.
const SHA256: &str = "d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11";

/// A pinned OpenSSH release, compiled with the only privilege-separation sandbox a
/// translated guest can run.
///
/// Only obtainable from [`OpenSshBuild::required_for`], so an image cannot end up
/// building its own sshd for an architecture whose packaged one works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenSshBuild {
    version: &'static str,
    sha256: &'static str,
    sandbox: &'static str,
}

impl OpenSshBuild {
    /// The build an image for `arch` needs, or `None` where the packaged sshd works.
    #[must_use]
    pub const fn required_for(arch: Arch) -> Option<Self> {
        // Translation is exactly the condition that breaks the packaged sshd, so it is
        // also exactly the condition under which one is compiled.
        if arch.needs_rosetta() {
            Some(Self {
                version: VERSION,
                sha256: SHA256,
                sandbox: SANDBOX,
            })
        } else {
            None
        }
    }

    /// Upstream version to fetch.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.version
    }

    /// Expected SHA-256 of the release tarball.
    #[must_use]
    pub const fn sha256(&self) -> &'static str {
        self.sha256
    }

    /// Value for `--with-sandbox`.
    #[must_use]
    pub const fn sandbox(&self) -> &'static str {
        self.sandbox
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_translated_image_compiles_its_own_sshd() {
        assert!(
            OpenSshBuild::required_for(Arch::Arm64).is_none(),
            "the native sshd's seccomp sandbox works, and is stronger than rlimit"
        );
        let build = OpenSshBuild::required_for(Arch::Amd64).unwrap();
        assert_eq!(build.version(), VERSION);
        assert_eq!(build.sha256().len(), 64, "a SHA-256 is 64 hex digits");
        assert_eq!(
            build.sandbox(),
            "no",
            "Rosetta supports neither of Linux's two mechanisms; a build that claims one \
             fails configure, or worse, fails at the first connection"
        );
    }
}
