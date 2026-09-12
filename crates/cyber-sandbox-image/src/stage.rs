use std::path::{Path, PathBuf};

use cyber_sandbox_runtime::{Arch, ImageBuild, ImageReference, RuntimeError};

use crate::{
    digest::ContextDigest,
    guest::{self, GuestError},
    layout::SandboxLayout,
    profile::ToolProfile,
    render::RenderedImage,
};

/// Files the builder needs from the workspace in order to compile the gateway.
const WORKSPACE_FILES: &[&str] = &["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"];

/// Errors raised while materialising an image build context.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// A template could not be rendered.
    #[error("failed to render the image templates")]
    Render(#[from] askama::Error),
    /// The staging directory could not be written.
    #[error("failed to stage the build context at {path}")]
    Io {
        /// Path being written when the failure occurred.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The repository and digest did not form a reference the runtime accepts.
    #[error("the image tag is not a valid reference")]
    Tag(#[from] RuntimeError),
    /// The workspace's dependency graph could not be followed.
    #[error("failed to work out which sources the image is compiled from")]
    Guest(#[from] GuestError),
    /// The staged context could not be read back to be digested.
    #[error("failed to digest the build context at {path}")]
    Digest {
        /// Directory being digested.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// A staged directory holding everything `container build` needs, and the digest that
/// names what it holds.
#[derive(Debug)]
pub struct BuildContext {
    directory: PathBuf,
    arch: Arch,
    digest: ContextDigest,
}

impl BuildContext {
    /// Renders the image and copies the workspace sources into a directory under `parent`
    /// named for their digest.
    ///
    /// The context is written to a directory of this process's own first and moved into
    /// place once its name is known, so two invocations staging at once — or one staging
    /// while a builder is still reading — never share a directory. A context that is
    /// already in place is used as it is: its name says it holds the same bytes.
    ///
    /// The digest covers the rendered files, the workspace manifests and the sources the
    /// guest programs are compiled from — not the sources of crates that are copied only
    /// so that Cargo can load the workspace. A change to the host's own code is not a
    /// change to the image.
    ///
    /// # Errors
    /// Fails when a template cannot be rendered, when the workspace sources cannot be
    /// read or followed, or when the staging directory cannot be written or read back.
    pub async fn stage(
        parent: impl Into<PathBuf>,
        workspace_root: &Path,
        base_image: &str,
        arch: Arch,
        profile: ToolProfile,
        layout: &SandboxLayout,
    ) -> Result<Self, StageError> {
        let parent = parent.into();
        let rendered = RenderedImage::render(base_image, arch, profile, layout)?;
        let closure = guest::source_closure(workspace_root)?;

        let directory = parent.join(format!("staging-{}", std::process::id()));
        remove_dir_all_if_present(&directory).await?;
        create_dir_all(&directory).await?;

        for file in WORKSPACE_FILES {
            copy_file(&workspace_root.join(file), &directory.join(file)).await?;
        }
        copy_tree(&workspace_root.join("crates"), &directory.join("crates")).await?;

        write_file(&directory.join("Dockerfile"), &rendered.dockerfile).await?;
        write_file(&directory.join("entrypoint.sh"), &rendered.entrypoint).await?;
        write_file(&directory.join("egress-policy.sh"), &rendered.egress_policy).await?;
        write_file(&directory.join("sshd_config"), &rendered.sshd_config).await?;
        write_file(&directory.join("claude.json"), &rendered.claude_config).await?;
        write_file(
            &directory.join("claude-settings.json"),
            &rendered.claude_settings,
        )
        .await?;
        write_file(&directory.join("devin-config.json"), &rendered.devin_config).await?;
        write_file(
            &directory.join("devin-trusted-workspaces.json"),
            &rendered.devin_trusted_workspaces,
        )
        .await?;
        write_file(&directory.join("sudoers"), &rendered.sudoers).await?;
        write_file(&directory.join("detonate.sh"), &rendered.detonate).await?;
        write_file(&directory.join("statusline.sh"), rendered.statusline).await?;

        // Read back from disk rather than summed up while writing, so that what is
        // digested is exactly what the builder will be handed.
        let digested = directory.clone();
        let digest = tokio::task::spawn_blocking(move || {
            ContextDigest::of_directory(&digested, |relative| {
                guest::shapes_the_image(relative, &closure)
            })
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|digest| digest)
        .map_err(|source| StageError::Digest {
            path: directory.clone(),
            source,
        })?;

        let settled = parent.join(digest.tag());
        match tokio::fs::rename(&directory, &settled).await {
            Ok(()) => {}
            // Another invocation got there first, with the same bytes under the same
            // name; what this one staged is surplus.
            Err(source)
                if source.kind() == std::io::ErrorKind::AlreadyExists
                    || source.kind() == std::io::ErrorKind::DirectoryNotEmpty =>
            {
                remove_dir_all_if_present(&directory).await?;
            }
            Err(source) => {
                return Err(StageError::Io {
                    path: settled,
                    source,
                });
            }
        }

        Ok(Self {
            directory: settled,
            arch,
            digest,
        })
    }

    /// Directory the context was staged into.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Digest of everything in the context.
    #[must_use]
    pub fn digest(&self) -> ContextDigest {
        self.digest
    }

    /// The reference an image built from this context is tagged with, under `repository`.
    ///
    /// The tag carries the architecture and the digest: the architecture because an
    /// `amd64` machine started from an `arm64` root filesystem cannot execute its own
    /// userspace, and the digest because an image built from other sources than the
    /// tool's is not the image the tool asked for, however recently it was built.
    ///
    /// # Errors
    /// Fails when `repository` does not form a reference the runtime accepts.
    pub fn reference(&self, repository: &str) -> Result<ImageReference, StageError> {
        Ok(ImageReference::new(format!(
            "{repository}:{}-{}",
            self.arch,
            self.digest.tag()
        ))?)
    }

    /// The build request to hand to the runtime, producing `tag`.
    #[must_use]
    pub fn build_request(&self, tag: ImageReference) -> ImageBuild {
        ImageBuild {
            tag,
            context: self.directory.clone(),
            dockerfile: self.directory.join("Dockerfile"),
            arch: self.arch,
            build_args: Vec::new(),
        }
    }
}

async fn remove_dir_all_if_present(path: &Path) -> Result<(), StageError> {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StageError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

async fn create_dir_all(path: &Path) -> Result<(), StageError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| StageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn copy_file(from: &Path, to: &Path) -> Result<(), StageError> {
    tokio::fs::copy(from, to)
        .await
        .map(drop)
        .map_err(|source| StageError::Io {
            path: from.to_path_buf(),
            source,
        })
}

async fn write_file(path: &Path, contents: &str) -> Result<(), StageError> {
    tokio::fs::write(path, contents)
        .await
        .map_err(|source| StageError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn copy_tree(from: &Path, to: &Path) -> Result<(), StageError> {
    create_dir_all(to).await?;
    let mut pending = vec![(from.to_path_buf(), to.to_path_buf())];
    while let Some((source_dir, target_dir)) = pending.pop() {
        let mut entries =
            tokio::fs::read_dir(&source_dir)
                .await
                .map_err(|source| StageError::Io {
                    path: source_dir.clone(),
                    source,
                })?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|source| StageError::Io {
                path: source_dir.clone(),
                source,
            })?
        {
            let source_path = entry.path();
            let target_path = target_dir.join(entry.file_name());
            let file_type = entry.file_type().await.map_err(|source| StageError::Io {
                path: source_path.clone(),
                source,
            })?;
            if file_type.is_dir() {
                create_dir_all(&target_path).await?;
                pending.push((source_path, target_path));
            } else {
                copy_file(&source_path, &target_path).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file the Dockerfile names in a `COPY` exists in the staged context.
    ///
    /// A rendered file that is never staged — or a COPY of a name nothing renders —
    /// fails inside `container build` with a message about the build context rather than
    /// the file, so the agreement is checked here where both sides of it are visible.
    #[tokio::test]
    async fn every_copy_source_the_dockerfile_names_is_staged() {
        let parent = tempfile::TempDir::new().unwrap();
        let context = BuildContext::stage(
            parent.path(),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .as_path(),
            "docker.io/kalilinux/kali-rolling:latest",
            Arch::Arm64,
            ToolProfile::Core,
            &SandboxLayout::default(),
        )
        .await
        .unwrap();

        let dockerfile = std::fs::read_to_string(context.directory().join("Dockerfile")).unwrap();
        for line in dockerfile.lines() {
            let Some(source) = line.strip_prefix("COPY ") else {
                continue;
            };
            // `COPY --from=<stage>` names a build stage's filesystem, not the context.
            let source = source.split_whitespace().next().unwrap();
            if source.starts_with("--") {
                continue;
            }
            assert!(
                context.directory().join(source).exists(),
                "the Dockerfile copies {source}, and nothing staged it"
            );
        }
    }
}
