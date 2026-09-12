use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt as _, BufReader, Lines},
    process::{Child, ChildStdout, Command},
};
use tracing::debug;

use crate::{
    budget::{Build, Reservation, Workload},
    error::RuntimeError,
    inspect::{ContainerState, RunState, SystemStatus},
    spec::{Arch, ContainerName, ContainerSpec, ImageReference},
};

/// Name the runtime registers the shared image builder under.
pub(crate) const BUILDER: &str = "buildkit";

/// Driver for the `container` CLI.
#[derive(Debug, Clone)]
pub struct AppleContainer {
    binary: PathBuf,
}

/// What a command run inside a container produced.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Standard output, decoded as UTF-8 lossily.
    pub stdout: String,
    /// Standard error, decoded as UTF-8 lossily.
    pub stderr: String,
}

/// A command running inside a container whose output the caller consumes line by line.
///
/// Kept distinct from [`ExecOutput`] because a followed audit trail never ends on its
/// own: there is no final output to collect, only records as the gateway writes them.
#[derive(Debug)]
pub struct ExecStream {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
    args: Vec<String>,
}

impl ExecStream {
    /// The next line the command wrote, or `None` once its output ends.
    ///
    /// # Errors
    /// Fails when the pipe cannot be read.
    pub async fn next_line(&mut self) -> Result<Option<String>, RuntimeError> {
        self.lines
            .next_line()
            .await
            .map_err(|source| RuntimeError::Stream {
                args: self.args.clone(),
                source,
            })
    }

    /// Waits for the command to exit.
    ///
    /// # Errors
    /// Fails when the command cannot be reaped or exited non-zero.
    pub async fn finish(mut self) -> Result<(), RuntimeError> {
        let status = self
            .child
            .wait()
            .await
            .map_err(|source| RuntimeError::Stream {
                args: self.args.clone(),
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(RuntimeError::Command {
                args: self.args,
                status: status.to_string(),
                stderr: "see the output above".to_owned(),
            })
        }
    }
}

/// Inputs for `container build`.
#[derive(Debug, Clone)]
pub struct ImageBuild {
    /// Tag to apply to the built image.
    pub tag: ImageReference,
    /// Directory used as the build context.
    pub context: PathBuf,
    /// Path to the Dockerfile, relative to the context or absolute.
    pub dockerfile: PathBuf,
    /// Target architecture of the produced image.
    pub arch: Arch,
    /// Build arguments passed through to the builder.
    pub build_args: Vec<(String, String)>,
}

/// One entry of `container image list --format json`.
#[derive(Debug, Deserialize)]
struct ImageListing {
    configuration: ImageListingConfiguration,
}

/// The part of an image's configuration that names it.
#[derive(Debug, Deserialize)]
struct ImageListingConfiguration {
    name: ImageReference,
}

impl AppleContainer {
    /// Locates the `container` binary on `PATH`.
    ///
    /// # Errors
    /// Returns [`RuntimeError::RuntimeMissing`] when the runtime is not installed.
    pub fn discover() -> Result<Self, RuntimeError> {
        let path = std::env::var_os("PATH").ok_or(RuntimeError::RuntimeMissing)?;
        std::env::split_paths(&path)
            .map(|directory| directory.join("container"))
            .find(|candidate| candidate.is_file())
            .map(|binary| Self { binary })
            .ok_or(RuntimeError::RuntimeMissing)
    }

    /// Wraps an explicit path to the `container` binary.
    #[must_use]
    pub fn at(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    /// Path of the runtime binary this driver invokes.
    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    /// The runtime's version banner.
    ///
    /// # Errors
    /// Fails when the runtime cannot be invoked or exits non-zero.
    pub async fn version(&self) -> Result<String, RuntimeError> {
        let stdout = self.output(&["--version"]).await?;
        Ok(stdout.trim().to_owned())
    }

    /// Health of the runtime's system services.
    ///
    /// # Errors
    /// Fails when the runtime cannot be invoked, exits non-zero, or reports a status
    /// this crate cannot parse.
    pub async fn system_status(&self) -> Result<SystemStatus, RuntimeError> {
        let args = ["system", "status", "--format", "json"];
        let stdout = self.output(&args).await?;
        serde_json::from_str(&stdout).map_err(|source| RuntimeError::Output {
            args: to_owned(&args),
            source,
        })
    }

    /// Starts the runtime's system services.
    ///
    /// # Errors
    /// Fails when the services cannot be started.
    pub async fn system_start(&self) -> Result<(), RuntimeError> {
        self.output(&["system", "start"]).await.map(drop)
    }

    /// Installs the recommended guest kernel for `arch`.
    ///
    /// # Errors
    /// Fails when the kernel cannot be downloaded or installed.
    pub async fn install_recommended_kernel(&self, arch: Arch) -> Result<(), RuntimeError> {
        self.output(&[
            "system",
            "kernel",
            "set",
            "--arch",
            arch.as_str(),
            "--recommended",
        ])
        .await
        .map(drop)
    }

    /// Starts a container from `spec` and leaves it running in the background.
    ///
    /// # Errors
    /// Fails when the runtime refuses the spec or the container does not start.
    pub async fn run_detached(&self, spec: &ContainerSpec) -> Result<ContainerName, RuntimeError> {
        let args = spec.render_run_arguments();
        self.output(&args).await?;
        Ok(spec.name.clone())
    }

    /// Reads the full state of one container.
    ///
    /// # Errors
    /// Fails when the container does not exist or the runtime output cannot be parsed.
    pub async fn inspect(&self, name: &ContainerName) -> Result<ContainerState, RuntimeError> {
        let args = ["inspect".to_owned(), name.to_string()];
        let stdout = self.output(&args).await?;
        let states: Vec<ContainerState> =
            serde_json::from_str(&stdout).map_err(|source| RuntimeError::Output {
                args: to_owned(&args),
                source,
            })?;
        states
            .into_iter()
            .next()
            .ok_or_else(|| RuntimeError::NoSuchContainer(name.clone()))
    }

    /// Lists every container the runtime knows about, running or not.
    ///
    /// # Errors
    /// Fails when the runtime cannot be invoked or its output cannot be parsed.
    pub async fn list(&self) -> Result<Vec<ContainerState>, RuntimeError> {
        let args = ["list", "--all", "--format", "json"];
        let stdout = self.output(&args).await?;
        serde_json::from_str(&stdout).map_err(|source| RuntimeError::Output {
            args: to_owned(&args),
            source,
        })
    }

    /// Runs `command` inside a running container and collects its output.
    ///
    /// # Errors
    /// Fails when the container is not running or the command exits non-zero.
    pub async fn exec<S>(
        &self,
        name: &ContainerName,
        command: &[S],
    ) -> Result<ExecOutput, RuntimeError>
    where
        S: AsRef<str>,
    {
        let mut args = vec!["exec".to_owned(), name.to_string()];
        args.extend(command.iter().map(|part| part.as_ref().to_owned()));
        let (stdout, stderr) = self.output_with_stderr(&args).await?;
        Ok(ExecOutput { stdout, stderr })
    }

    /// Runs `command` inside a running container as `user`.
    ///
    /// # Errors
    /// Fails when the container is not running or the command exits non-zero.
    pub async fn exec_as<S>(
        &self,
        name: &ContainerName,
        user: &str,
        command: &[S],
    ) -> Result<ExecOutput, RuntimeError>
    where
        S: AsRef<str>,
    {
        let mut args = vec![
            "exec".to_owned(),
            "--user".to_owned(),
            user.to_owned(),
            name.to_string(),
        ];
        args.extend(command.iter().map(|part| part.as_ref().to_owned()));
        let (stdout, stderr) = self.output_with_stderr(&args).await?;
        Ok(ExecOutput { stdout, stderr })
    }

    /// Runs `command` inside a running container with this process's stdio attached.
    ///
    /// Used where the output is the point rather than something to parse — following the
    /// audit trail, for instance — so the caller sees it as it is produced.
    ///
    /// # Errors
    /// Fails when the container is not running or the command exits non-zero.
    pub async fn exec_inherit<S>(
        &self,
        name: &ContainerName,
        user: &str,
        command: &[S],
    ) -> Result<(), RuntimeError>
    where
        S: AsRef<str>,
    {
        let mut args = vec![
            "exec".to_owned(),
            "--user".to_owned(),
            user.to_owned(),
            name.to_string(),
        ];
        args.extend(command.iter().map(|part| part.as_ref().to_owned()));
        self.status(&args).await
    }

    /// Runs `command` inside a running container and hands back its output line by line.
    ///
    /// # Errors
    /// Fails when the invocation cannot be spawned.
    pub fn exec_streaming<S>(
        &self,
        name: &ContainerName,
        user: &str,
        command: &[S],
    ) -> Result<ExecStream, RuntimeError>
    where
        S: AsRef<str>,
    {
        let mut args = vec![
            "exec".to_owned(),
            "--user".to_owned(),
            user.to_owned(),
            name.to_string(),
        ];
        args.extend(command.iter().map(|part| part.as_ref().to_owned()));
        debug!(binary = %self.binary.display(), args = ?args, "streaming from container runtime");
        let mut child = Command::new(&self.binary)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|source| RuntimeError::Spawn {
                binary: self.binary.clone(),
                args: args.clone(),
                source,
            })?;
        let stdout = child.stdout.take().ok_or_else(|| RuntimeError::Stream {
            args: args.clone(),
            source: std::io::Error::other("the runtime's stdout was not captured"),
        })?;
        Ok(ExecStream {
            child,
            lines: BufReader::new(stdout).lines(),
            args,
        })
    }

    /// Whether the runtime already holds an image under `reference`.
    ///
    /// # Errors
    /// Fails when the runtime cannot be invoked at all. A missing image is reported as
    /// `Ok(false)` rather than an error, because that is the question being asked.
    pub async fn image_exists(&self, reference: &ImageReference) -> Result<bool, RuntimeError> {
        let args = [
            "image".to_owned(),
            "inspect".to_owned(),
            reference.to_string(),
        ];
        match self.output(&args).await {
            Ok(_) => Ok(true),
            Err(RuntimeError::Command { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Every image the runtime holds, by the reference it was built or pulled under.
    ///
    /// # Errors
    /// Fails when the runtime cannot be invoked, when its output cannot be parsed, or when
    /// it reports an image under a name that is not a reference.
    pub async fn image_list(&self) -> Result<Vec<ImageReference>, RuntimeError> {
        let args = ["image", "list", "--format", "json"];
        let stdout = self.output(&args).await?;
        let images: Vec<ImageListing> =
            serde_json::from_str(&stdout).map_err(|source| RuntimeError::Output {
                args: to_owned(&args),
                source,
            })?;
        Ok(images
            .into_iter()
            .map(|image| image.configuration.name)
            .collect())
    }

    /// Pulls an image the registry holds.
    ///
    /// The platform is pinned because a session's architecture is its own rather than
    /// the host's: an `amd64` session on an arm64 host needs the amd64 image, and a
    /// registry answer left to default to the host's platform would hand back one the
    /// machine cannot boot.
    ///
    /// Quiet by choice: a pull is also how a staged image asks the registry whether it
    /// was ever published, and a miss there is an ordinary step towards a local build
    /// rather than an error the researcher should watch scroll by.
    ///
    /// # Errors
    /// Fails when the registry does not hold the reference, or the pull cannot finish.
    pub async fn image_pull(
        &self,
        reference: &ImageReference,
        arch: Arch,
    ) -> Result<(), RuntimeError> {
        self.output(&[
            "image".to_owned(),
            "pull".to_owned(),
            "--platform".to_owned(),
            format!("linux/{}", arch.as_str()),
            reference.to_string(),
        ])
        .await
        .map(drop)
    }

    /// Deletes an image the runtime holds.
    ///
    /// # Errors
    /// Fails when the runtime does not hold the image, or refuses to delete it — as it
    /// does while a container created from it still exists.
    pub async fn image_remove(&self, reference: &ImageReference) -> Result<(), RuntimeError> {
        let args = [
            "image".to_owned(),
            "delete".to_owned(),
            reference.to_string(),
        ];
        self.output(&args).await.map(drop)
    }

    /// Starts a container that already exists.
    ///
    /// Takes a reservation for the same reason `run_detached` does. A stopped machine
    /// costs the host nothing and a started one costs its whole allocation, so starting
    /// one is an allocation like any other and has to be checked against the host first.
    /// The machine's own size is what the caller must have reserved: a machine sized
    /// differently is refused rather than started against a budget checked for something
    /// else.
    ///
    /// # Errors
    /// Fails when the runtime does not know the container, when its allocation is not the
    /// one that was reserved, or when the runtime refuses to start it.
    pub async fn start<W: Workload>(
        &self,
        name: &ContainerName,
        reservation: &Reservation<W>,
    ) -> Result<(), RuntimeError> {
        let resources = self.inspect(name).await?.configuration.resources;
        if !resources.matches(reservation) {
            return Err(RuntimeError::InvalidValue {
                kind: "reservation for a container that already exists",
                value: format!(
                    "{} vCPUs / {} MiB reserved for a machine of {} vCPUs / {} MiB",
                    reservation.cpus(),
                    reservation.memory().as_mib(),
                    resources.cpus,
                    resources.memory_in_bytes / (1024 * 1024),
                ),
                reason: "a machine's size is fixed when it is created",
            });
        }
        self.output(&["start".to_owned(), name.to_string()])
            .await
            .map(drop)
    }

    /// Stops a running container.
    ///
    /// # Errors
    /// Fails when the container cannot be stopped.
    pub async fn stop(&self, name: &ContainerName) -> Result<(), RuntimeError> {
        self.output(&["stop".to_owned(), name.to_string()])
            .await
            .map(drop)
    }

    /// Deletes a container, killing it first when it is still running.
    ///
    /// # Errors
    /// Fails when the container cannot be deleted.
    pub async fn remove(&self, name: &ContainerName) -> Result<(), RuntimeError> {
        self.output(&["delete".to_owned(), "--force".to_owned(), name.to_string()])
            .await
            .map(drop)
    }

    /// Builds an image, streaming the builder's progress to this process's stderr.
    ///
    /// Takes a reservation rather than building with whatever builder happens to exist:
    /// the builder is a persistent VM whose sizing is fixed at creation, and an uncapped
    /// one is what exhausted this host on 2026-09-03.
    ///
    /// # Errors
    /// Fails when the builder cannot be brought up at `reservation`'s sizing, or when the
    /// build itself exits non-zero.
    pub async fn build(
        &self,
        build: &ImageBuild,
        reservation: &Reservation<Build>,
    ) -> Result<(), RuntimeError> {
        self.ensure_builder(reservation).await?;
        let mut args = vec![
            "build".to_owned(),
            "--tag".to_owned(),
            build.tag.to_string(),
            "--file".to_owned(),
            build.dockerfile.display().to_string(),
            "--arch".to_owned(),
            build.arch.as_str().to_owned(),
        ];
        for (key, value) in &build.build_args {
            args.push("--build-arg".to_owned());
            args.push(format!("{key}={value}"));
        }
        args.push(build.context.display().to_string());
        self.status(&args).await
    }

    /// Brings the shared builder up at exactly `reservation`'s sizing.
    ///
    /// A builder that already runs at that sizing is left alone, so its layer cache
    /// survives. One created with a different allocation is deleted and recreated: the
    /// allocation cannot be changed in place, and reusing an unknown one defeats the
    /// budget.
    ///
    /// # Errors
    /// Fails when the builder cannot be listed, deleted or started.
    pub async fn ensure_builder(
        &self,
        reservation: &Reservation<Build>,
    ) -> Result<(), RuntimeError> {
        match self.builder().await? {
            Some(state) if state.configuration.resources.matches(reservation) => {
                if state.status.state == RunState::Running {
                    return Ok(());
                }
            }
            Some(state) => {
                debug!(
                    cpus = state.configuration.resources.cpus,
                    memory = state.configuration.resources.memory_in_bytes,
                    "the existing builder is not sized to the host's budget; recreating it"
                );
                self.output(&["builder", "delete", "--force"]).await?;
            }
            None => {}
        }
        self.output(&[
            "builder",
            "start",
            "--cpus",
            &reservation.cpus().to_string(),
            "--memory",
            &reservation.memory().to_string(),
        ])
        .await
        .map(drop)
    }

    /// The shared image builder, when the runtime holds one.
    ///
    /// # Errors
    /// Fails when the runtime's container list cannot be read.
    pub async fn builder(&self) -> Result<Option<ContainerState>, RuntimeError> {
        Ok(self
            .list()
            .await?
            .into_iter()
            .find(|container| container.id.as_str() == BUILDER))
    }

    async fn output<S: AsRef<OsStr> + AsRef<str>>(
        &self,
        args: &[S],
    ) -> Result<String, RuntimeError> {
        self.output_with_stderr(args)
            .await
            .map(|(stdout, _)| stdout)
    }

    async fn output_with_stderr<S: AsRef<OsStr> + AsRef<str>>(
        &self,
        args: &[S],
    ) -> Result<(String, String), RuntimeError> {
        debug!(binary = %self.binary.display(), args = ?to_owned(args), "invoking container runtime");
        let output = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|source| RuntimeError::Spawn {
                binary: self.binary.clone(),
                args: to_owned(args),
                source,
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if !output.status.success() {
            return Err(RuntimeError::Command {
                args: to_owned(args),
                status: output.status.to_string(),
                stderr,
            });
        }
        Ok((String::from_utf8_lossy(&output.stdout).into_owned(), stderr))
    }

    async fn status<S: AsRef<OsStr> + AsRef<str>>(&self, args: &[S]) -> Result<(), RuntimeError> {
        let status = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::null())
            .status()
            .await
            .map_err(|source| RuntimeError::Spawn {
                binary: self.binary.clone(),
                args: to_owned(args),
                source,
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(RuntimeError::Command {
                args: to_owned(args),
                status: status.to_string(),
                stderr: "see the output above".to_owned(),
            })
        }
    }
}

fn to_owned<S: AsRef<str>>(args: &[S]) -> Vec<String> {
    args.iter().map(|arg| arg.as_ref().to_owned()).collect()
}
