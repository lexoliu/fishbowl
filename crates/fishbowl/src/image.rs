//! Sourcing the sandbox image, which nobody asks for directly.
//!
//! The image is an implementation detail of a session: it is pulled when the registry
//! already holds what the tool would build, and built locally only when it does not —
//! which is to say, when the sources it is staged from were never published. There is
//! no command for either, because a researcher asking for an environment has no reason
//! to know that one of the steps is a Kali image with the audit gateway compiled into
//! it.
//!
//! The image is named for the digest of its build context, so the question "does the
//! runtime hold the image this tool would build?" is answered by looking the name up
//! rather than by trusting that whatever was fetched last is still right. CI pushes the
//! same tag after building the same staged context, so a pull hit is by construction
//! the image a local build would have produced; a miss means these sources were never
//! published, and building them is the only way to have the image.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use fishbowl_image::{BuildContext, DEFAULT_BASE_IMAGE, DEFAULT_PROFILE};
use fishbowl_runtime::{Arch, Build, ImageReference};

use crate::{cli, host::Host};

/// Bytes in a gibibyte, for reporting free space.
const GIB: u64 = 1024 * 1024 * 1024;

/// Crate whose presence proves the given directory really is the fishbowl workspace.
const GATEWAY_CRATE: &str = "crates/fishbowl-gateway/Cargo.toml";

/// Where the image a session starts from comes from.
#[derive(Debug)]
pub enum Source {
    /// Staged from a checkout this invocation can see: pull the digest tag when the
    /// registry already holds it, build it when it does not.
    Staged(Staged),
    /// The image this version of the tool was published as. With no checkout there is
    /// nothing to build from, so pulling it is the whole job.
    Published(ImageReference),
}

impl Source {
    /// The image this source answers to.
    pub fn tag(&self) -> &ImageReference {
        match self {
            Self::Staged(staged) => staged.tag(),
            Self::Published(reference) => reference,
        }
    }
}

/// A build context staged from the workspace, and the name of the image it produces.
#[derive(Debug)]
pub struct Staged {
    context: BuildContext,
    tag: ImageReference,
}

impl Staged {
    /// The image a session of this architecture starts from, whether or not it has been
    /// built yet.
    #[must_use]
    pub fn tag(&self) -> &ImageReference {
        &self.tag
    }
}

/// Works out where the image for `arch` comes from.
///
/// A checkout in hand — named by `--workspace`, or the working directory itself —
/// means the sources on disk are what the guest's courier and gateway must agree with,
/// so the context is staged from them and the image named for their digest. Anywhere
/// else there is nothing to build from and nothing to disagree with, and the image is
/// the one this version of the tool was published as.
///
/// # Errors
/// Fails when an explicit `--workspace` is not a fishbowl checkout, when the
/// context cannot be staged, or when the published tag is not a reference.
pub async fn source(host: &Host, workspace: Option<&Path>, arch: Arch) -> Result<Source> {
    let root = match workspace {
        Some(directory) => checkout(directory)?.with_context(|| {
            format!(
                "{} does not hold {GATEWAY_CRATE}; point `--workspace` at a fishbowl \
                 checkout, or leave it off entirely so the image this version was \
                 published as is pulled instead",
                directory.display()
            )
        })?,
        None => match checkout(Path::new("."))? {
            Some(root) => root,
            None => return published(arch).map(Source::Published),
        },
    };
    stage(host, &root, arch).await.map(Source::Staged)
}

/// Makes sure the runtime holds the image `source` names, fetching or building it.
///
/// # Errors
/// Fails when a published image cannot be pulled — there is nothing else to try —
/// or when a staged one can be neither pulled nor built.
pub async fn ensure(host: &Host, source: &Source, arch: Arch) -> Result<()> {
    let tag = source.tag();
    if host.runtime().image_exists(tag).await? {
        tracing::debug!(image = %tag, "the sandbox image is already here");
        return Ok(());
    }

    let Source::Staged(staged) = source else {
        tracing::info!(image = %tag, "pulling the sandbox image this version was published as");
        return host.runtime().image_pull(tag, arch).await.with_context(|| {
            format!(
                "pulling {tag}. If this build of fishbowl is not a released version, \
                 no image was published for it; run from a checkout so it is built \
                 instead"
            )
        });
    };

    match host.runtime().image_pull(tag, arch).await {
        Ok(()) => {
            tracing::info!(
                image = %tag,
                "pulled the sandbox image, already built from these sources"
            );
            return Ok(());
        }
        Err(error) => {
            tracing::debug!(
                image = %tag,
                %error,
                "the registry does not hold this image; building it locally"
            );
        }
    }
    tracing::info!(
        image = %tag,
        "building the sandbox image, because it was never built from these sources"
    );

    let budget = host.budget().await?;
    let reservation = budget.suggest::<Build>()?;
    tracing::info!(
        cpus = %reservation.cpus(),
        memory = %reservation.memory(),
        free_disk_gib = budget.free_disk() / GIB,
        "the host can carry this build"
    );

    host.runtime()
        .build(
            &staged.context.build_request(staged.tag.clone()),
            &reservation,
        )
        .await
        .context("building the sandbox image")
}

/// Stages the build context for architecture `arch` and names the image it describes.
///
/// Cheap next to a build — a render and a copy of the sources — and done for every new
/// session staged from a checkout, because the name is the only way to know whether the
/// image these sources describe already exists.
///
/// # Errors
/// Fails when the workspace sources cannot be followed or the build context cannot be
/// staged.
async fn stage(host: &Host, workspace: &Path, arch: Arch) -> Result<Staged> {
    let staging = host.build_directory().join(arch.as_str());

    tracing::debug!(
        arch = %arch,
        profile = %DEFAULT_PROFILE,
        workspace = %workspace.display(),
        "staging the sandbox image build context"
    );

    let context = BuildContext::stage(
        staging,
        workspace,
        DEFAULT_BASE_IMAGE,
        arch,
        DEFAULT_PROFILE,
        host.layout(),
    )
    .await
    .context("staging the image build context")?;
    let tag = context
        .reference(cli::IMAGE_REPOSITORY)
        .context("naming the sandbox image")?;
    Ok(Staged { context, tag })
}

/// The reference this version's image was published under, per architecture.
fn published(arch: Arch) -> Result<ImageReference> {
    ImageReference::new(format!(
        "{}:{arch}-{}",
        cli::IMAGE_REPOSITORY,
        env!("CARGO_PKG_VERSION")
    ))
    .context("naming the published sandbox image")
}

/// The fishbowl checkout rooted at `directory`, when there is one.
///
/// The check is explicit rather than implicit because the builder's own error for a
/// missing crate is a wall of Cargo output that says nothing about the real cause.
fn checkout(directory: &Path) -> Result<Option<PathBuf>> {
    let root = directory
        .canonicalize()
        .with_context(|| format!("resolving the workspace {}", directory.display()))?;
    Ok(root.join(GATEWAY_CRATE).is_file().then_some(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_tag_names_the_version_and_the_architecture() {
        let reference = published(Arch::Arm64).unwrap();
        assert_eq!(
            reference.as_str(),
            format!(
                "ghcr.io/lexoliu/fishbowl:arm64-{}",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn a_directory_that_is_not_a_checkout_is_not_mistaken_for_one() {
        let directory = tempfile::tempdir().unwrap();
        assert!(checkout(directory.path()).unwrap().is_none());
    }

    #[test]
    fn a_checkout_is_found_where_the_gateway_sources_are() {
        assert_eq!(
            checkout(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .as_path()
            )
            .unwrap()
            .map(|root| root.join(GATEWAY_CRATE).is_file()),
            Some(true)
        );
    }
}
