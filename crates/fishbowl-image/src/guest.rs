//! Which of the workspace's crates the image compiles, and which sources they are made of.
//!
//! The Dockerfile copies the whole `crates/` tree because Cargo will not build two members
//! of a workspace without every member's manifest in place. But only the guest programs
//! are compiled from it, so only their sources — and the sources of the crates they depend
//! on by path — can change what the image holds. Anything else in the tree is copied and
//! ignored, and changing it must not make the image a different image.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// The workspace members compiled into the image.
///
/// The gateway audits the session's egress and the courier lends the host's Claude Code
/// credential to the copy running inside; both are Linux-only and neither is built on the
/// host.
pub const GUEST_CRATES: &[&str] = &["fishbowl-gateway", "fishbowl-courier"];

/// Directory under the workspace root the crates live in.
const CRATES: &str = "crates";

/// Errors raised while following a workspace's dependency graph.
#[derive(Debug, thiserror::Error)]
pub enum GuestError {
    /// A manifest could not be read.
    #[error("failed to read {path}")]
    Read {
        /// Manifest being read.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// A manifest is not valid TOML.
    #[error("failed to parse {path}")]
    Parse {
        /// Manifest being parsed.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: toml::de::Error,
    },
    /// A dependency is inherited from the workspace, but the workspace does not declare it.
    #[error("{manifest} inherits `{dependency}` from the workspace, which does not declare it")]
    Undeclared {
        /// Manifest naming the dependency.
        manifest: PathBuf,
        /// Dependency name.
        dependency: String,
    },
}

/// The directory names under `crates/` whose sources the guest programs are compiled from:
/// [`GUEST_CRATES`] themselves and, transitively, every workspace crate they depend on.
///
/// Dependencies are followed through both forms the workspace uses — `path = "…"` on the
/// dependency itself and `workspace = true` resolved against `[workspace.dependencies]` —
/// and through `[build-dependencies]` as well as `[dependencies]`. Development
/// dependencies are not compiled into a release binary and are not followed.
///
/// # Errors
/// Fails when a manifest cannot be read or parsed, or when a dependency is inherited from
/// a workspace that does not declare it.
pub fn source_closure(workspace_root: &Path) -> Result<BTreeSet<String>, GuestError> {
    let root_manifest = workspace_root.join("Cargo.toml");
    let root = read_manifest(&root_manifest)?;
    let workspace_dependencies = root
        .get("workspace")
        .and_then(|workspace| workspace.get("dependencies"))
        .and_then(toml::Value::as_table);

    let mut closure = BTreeSet::new();
    let mut pending: Vec<String> = GUEST_CRATES.iter().map(|&name| name.to_owned()).collect();
    while let Some(directory) = pending.pop() {
        if !closure.insert(directory.clone()) {
            continue;
        }
        let manifest_path = workspace_root
            .join(CRATES)
            .join(&directory)
            .join("Cargo.toml");
        let manifest = read_manifest(&manifest_path)?;
        for section in ["dependencies", "build-dependencies"] {
            let Some(dependencies) = manifest.get(section).and_then(toml::Value::as_table) else {
                continue;
            };
            for (name, declaration) in dependencies {
                let mut path = path_of(declaration);
                if path.is_none() && inherits_from_workspace(declaration) {
                    let declared = workspace_dependencies
                        .and_then(|table| table.get(name))
                        .ok_or_else(|| GuestError::Undeclared {
                            manifest: manifest_path.clone(),
                            dependency: name.clone(),
                        })?;
                    path = path_of(declared);
                }
                if let Some(path) = path
                    && let Some(directory) = crate_directory(path)
                {
                    pending.push(directory);
                }
            }
        }
    }
    Ok(closure)
}

/// Whether `relative`, a path inside a staged build context, is one the image's programs
/// are compiled from — or a file outside the crate tree, which is always the image's.
///
/// A crate outside `closure` contributes only its manifest, which Cargo reads to load the
/// workspace, and none of its sources, which nothing in the image compiles.
#[must_use]
pub fn shapes_the_image(relative: &Path, closure: &BTreeSet<String>) -> bool {
    let mut components = relative.components();
    let Some(first) = components.next() else {
        return true;
    };
    if first.as_os_str() != CRATES {
        return true;
    }
    let Some(directory) = components.next() else {
        return true;
    };
    let directory = directory.as_os_str().to_string_lossy();
    if closure.contains(directory.as_ref()) {
        return true;
    }
    relative
        .file_name()
        .is_some_and(|name| name == "Cargo.toml")
        && components.clone().count() == 1
}

fn read_manifest(path: &Path) -> Result<toml::Table, GuestError> {
    let text = std::fs::read_to_string(path).map_err(|source| GuestError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| GuestError::Parse {
        path: path.to_path_buf(),
        source,
    })
}

fn path_of(declaration: &toml::Value) -> Option<&str> {
    declaration.get("path").and_then(toml::Value::as_str)
}

fn inherits_from_workspace(declaration: &toml::Value) -> bool {
    declaration
        .get("workspace")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
}

/// The directory under `crates/` a dependency path names, if it names one.
fn crate_directory(path: &str) -> Option<String> {
    let path = Path::new(path);
    let mut components = path.components();
    let under_crates = components
        .next()
        .is_some_and(|first| first.as_os_str() == CRATES);
    let directory = components.next()?;
    (under_crates && components.next().is_none())
        .then(|| directory.as_os_str().to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn the_image_is_shaped_by_the_guest_programs_and_what_they_are_made_of() {
        let closure = source_closure(&workspace()).unwrap();
        assert_eq!(
            closure,
            BTreeSet::from([
                "fishbowl-audit".to_owned(),
                "fishbowl-courier".to_owned(),
                "fishbowl-creds".to_owned(),
                "fishbowl-gateway".to_owned(),
            ]),
            "the host CLI, the agents crate, the image crate and the runtime are copied \
             into the context for Cargo's sake and compiled by nothing in it"
        );
    }

    #[test]
    fn a_host_crates_sources_do_not_shape_the_image_but_its_manifest_does() {
        let closure = BTreeSet::from(["fishbowl-gateway".to_owned()]);
        assert!(shapes_the_image(Path::new("Dockerfile"), &closure));
        assert!(shapes_the_image(Path::new("Cargo.lock"), &closure));
        assert!(shapes_the_image(
            Path::new("crates/fishbowl-gateway/src/main.rs"),
            &closure
        ));
        assert!(shapes_the_image(
            Path::new("crates/fishbowl/Cargo.toml"),
            &closure
        ));
        assert!(
            !shapes_the_image(Path::new("crates/fishbowl/src/cli.rs"), &closure),
            "a change to the host's command line is not a reason to rebuild a Kali image"
        );
        assert!(
            !shapes_the_image(Path::new("crates/fishbowl/templates/Cargo.toml"), &closure),
            "only the crate's own manifest, not any file that happens to share its name"
        );
    }
}
