//! What an image is named for.
//!
//! An image holds this repository's own programs — the gateway, the courier, the sshd
//! drop-in, the egress policy, the agents' first-run answers — and a tag that only says
//! which architecture it was built for cannot say whether it was built from the sources
//! the tool now has. Named for the digest of its build context instead, an image either
//! matches the tool that would build it or it is not the image the tool asks for, and an
//! upgrade rebuilds by nature while an unchanged tool never does.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};

/// How many hexadecimal digits of the digest name an image.
///
/// Twelve, which is 48 bits: enough that two builds from different sources cannot be
/// expected to collide on one host in the lifetime of the tool, and short enough to read
/// in a listing.
const TAG_DIGITS: usize = 12;

/// The SHA-256 digest of a staged build context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextDigest([u8; 32]);

impl ContextDigest {
    /// Digests every file under `directory` for which `included` holds, given its path
    /// relative to `directory`.
    ///
    /// Files are taken in the order of their paths, and each contributes its path, its
    /// length and its bytes, so that neither the order the filesystem lists them in nor a
    /// byte moving from one file's end to the next one's start changes nothing. What is
    /// not included is anything the build does not read: modes, timestamps, and the
    /// directory the context happens to be staged in.
    ///
    /// # Errors
    /// Fails when a file or directory under `directory` cannot be read.
    pub fn of_directory(
        directory: &Path,
        included: impl Fn(&Path) -> bool,
    ) -> std::io::Result<Self> {
        let mut files = Vec::new();
        collect(directory, directory, &mut files)?;
        files.retain(|relative| included(relative));
        files.sort();

        let mut hasher = Sha256::new();
        for relative in files {
            let contents = std::fs::read(directory.join(&relative))?;
            hasher.update(relative.as_os_str().as_encoded_bytes());
            hasher.update([0]);
            hasher.update((contents.len() as u64).to_le_bytes());
            hasher.update(&contents);
        }
        Ok(Self(hasher.finalize().into()))
    }

    /// The digits of the digest an image is tagged with.
    #[must_use]
    pub fn tag(&self) -> String {
        let mut tag = String::with_capacity(TAG_DIGITS);
        for byte in &self.0 {
            use std::fmt::Write as _;
            write!(tag, "{byte:02x}").expect("writing to a string cannot fail");
            if tag.len() >= TAG_DIGITS {
                break;
            }
        }
        tag.truncate(TAG_DIGITS);
        tag
    }
}

impl fmt::Display for ContextDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Lists every file under `directory`, by its path relative to `root`.
fn collect(root: &Path, directory: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("a path found under the root is under the root");
            files.push(relative.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        for (name, contents) in files {
            let path = directory.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        directory
    }

    #[test]
    fn the_same_context_staged_twice_has_one_digest() {
        let files: &[(&str, &[u8])] = &[
            ("Dockerfile", b"FROM kali"),
            ("crates/a/x.rs", b"fn a() {}"),
        ];
        let first = ContextDigest::of_directory(staged(files).path(), |_| true).unwrap();
        let second = ContextDigest::of_directory(staged(files).path(), |_| true).unwrap();
        assert_eq!(
            first, second,
            "the directory it is staged in is not part of what the build reads"
        );
    }

    #[test]
    fn a_changed_byte_anywhere_changes_the_digest() {
        let before = ContextDigest::of_directory(
            staged(&[
                ("Dockerfile", b"FROM kali"),
                ("crates/a/x.rs", b"fn a() {}"),
            ])
            .path(),
            |_| true,
        )
        .unwrap();
        let after = ContextDigest::of_directory(
            staged(&[
                ("Dockerfile", b"FROM kali"),
                ("crates/a/x.rs", b"fn b() {}"),
            ])
            .path(),
            |_| true,
        )
        .unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn a_byte_moving_between_files_changes_the_digest() {
        let one =
            ContextDigest::of_directory(staged(&[("a", b"xy"), ("b", b"z")]).path(), |_| true)
                .unwrap();
        let other =
            ContextDigest::of_directory(staged(&[("a", b"x"), ("b", b"yz")]).path(), |_| true)
                .unwrap();
        assert_ne!(
            one, other,
            "without lengths in the hash, the concatenation of the two contexts is the same"
        );
    }

    #[test]
    fn a_file_renamed_changes_the_digest() {
        let one = ContextDigest::of_directory(staged(&[("a", b"x")]).path(), |_| true).unwrap();
        let other = ContextDigest::of_directory(staged(&[("b", b"x")]).path(), |_| true).unwrap();
        assert_ne!(one, other, "the Dockerfile copies files by name");
    }

    #[test]
    fn a_file_the_filter_leaves_out_changes_nothing() {
        let without = ContextDigest::of_directory(staged(&[("a", b"x")]).path(), |_| true).unwrap();
        let with = ContextDigest::of_directory(
            staged(&[("a", b"x"), ("ignored/b", b"y")]).path(),
            |relative| !relative.starts_with("ignored"),
        )
        .unwrap();
        assert_eq!(without, with);
    }

    #[test]
    fn the_tag_is_a_fixed_prefix_of_the_hex_digest() {
        let digest = ContextDigest::of_directory(staged(&[("a", b"x")]).path(), |_| true).unwrap();
        let full = digest.to_string();
        assert_eq!(full.len(), 64);
        assert_eq!(digest.tag(), full[..TAG_DIGITS]);
        assert!(digest.tag().chars().all(|c| c.is_ascii_hexdigit()));
    }
}
