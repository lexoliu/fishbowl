use std::path::PathBuf;

use crate::spec::ContainerName;

/// Everything that can go wrong while driving `apple/container`.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The `container` binary is not on `PATH`.
    #[error("the `container` runtime is not installed; install it with `brew install container`")]
    RuntimeMissing,

    /// A `container` invocation could not be spawned.
    #[error("failed to spawn `{binary} {args}`", args = .args.join(" "))]
    Spawn {
        /// Path of the runtime binary.
        binary: PathBuf,
        /// Arguments the invocation was given.
        args: Vec<String>,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A `container` invocation exited non-zero.
    #[error("`container {args}` exited with {status}: {stderr}", args = .args.join(" "))]
    Command {
        /// Arguments the invocation was given.
        args: Vec<String>,
        /// Exit status text reported by the OS.
        status: String,
        /// Trimmed stderr from the runtime.
        stderr: String,
    },

    /// A streamed invocation's output could not be read, or the command not reaped.
    #[error("failed to read the output of `container {args}`", args = .args.join(" "))]
    Stream {
        /// Arguments the invocation was given.
        args: Vec<String>,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The runtime produced output this crate could not parse.
    #[error("could not parse the output of `container {args}`", args = .args.join(" "))]
    Output {
        /// Arguments the invocation was given.
        args: Vec<String>,
        /// Underlying deserialisation error.
        #[source]
        source: serde_json::Error,
    },

    /// `container inspect` returned no entry for a container that was expected to exist.
    #[error("the runtime reports no container named `{0}`")]
    NoSuchContainer(ContainerName),

    /// The host cannot carry a workload the caller asked to start.
    #[error("the host cannot run {workload}: it needs {needed}, but {available}")]
    Budget {
        /// Workload that was refused.
        workload: &'static str,
        /// What the workload asked for.
        needed: String,
        /// What the host actually has, phrased as a clause completing the message.
        available: String,
    },

    /// A property of the host could not be measured.
    #[error("could not measure the host's {what}: {reason}")]
    Probe {
        /// Property that could not be read.
        what: &'static str,
        /// Why it could not be read.
        reason: String,
    },

    /// A helper invoked while provisioning the toolchain exited non-zero.
    #[error("`{program} {args}` exited with {status}: {stderr}", args = .args.join(" "))]
    Helper {
        /// The tool that was run.
        program: &'static str,
        /// Arguments it was given.
        args: Vec<String>,
        /// Exit status text reported by the OS.
        status: String,
        /// What it wrote to stderr.
        stderr: String,
    },

    /// A fetched toolchain artifact does not hash to the digest pinned for it.
    #[error("{name} hashed to sha256:{actual}; this build pins sha256:{expected}")]
    Digest {
        /// The artifact that mismatched.
        name: &'static str,
        /// The digest this build pins.
        expected: &'static str,
        /// What the download actually hashed to.
        actual: String,
    },

    /// The toolchain could not be staged or committed on disk.
    #[error("could not {action} {path}: {source}")]
    Stage {
        /// What was being done.
        action: &'static str,
        /// Where.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A value that must satisfy the runtime's naming rules did not.
    #[error("`{value}` is not a valid {kind}: {reason}")]
    InvalidValue {
        /// What kind of value was being constructed.
        kind: &'static str,
        /// The rejected value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}
