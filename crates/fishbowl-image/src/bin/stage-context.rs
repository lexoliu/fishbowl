//! Stages an image build context and prints the tag it is pushed under.
//!
//! CI runs this where the CLI cannot go: the sandbox image is built on a runner, not on
//! the machine asking for a session, and the runner needs the same staged context — and
//! the same content digest — the CLI would have produced. With both coming from one
//! code path, an image the registry already holds under a digest tag is byte-for-byte
//! what a local build of the same sources would have made, and pulling it is never a
//! different image.
//!
//! The tag suffix (`<arch>-<digest>`) is the only line on stdout so a workflow can
//! capture it; diagnostics go to stderr.

use std::{path::PathBuf, process::ExitCode};

use clap::Parser;
use fishbowl_image::{BuildContext, DEFAULT_BASE_IMAGE, DEFAULT_PROFILE, SandboxLayout};
use fishbowl_runtime::Arch;

/// Stage a sandbox image build context for a CI build.
#[derive(Debug, Parser)]
#[command(name = "stage-context", about)]
struct Arguments {
    /// Checkout the guest programs are compiled from.
    #[arg(long)]
    workspace: PathBuf,
    /// Architecture the image targets.
    #[arg(long)]
    arch: Arch,
    /// Directory the context is staged under.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime can always be built");
    let context = match runtime.block_on(BuildContext::stage(
        &arguments.out,
        &arguments.workspace,
        DEFAULT_BASE_IMAGE,
        arguments.arch,
        DEFAULT_PROFILE,
        &SandboxLayout::default(),
    )) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("stage-context: {error}");
            return ExitCode::FAILURE;
        }
    };
    println!("{}-{}", arguments.arch.as_str(), context.digest().tag());
    ExitCode::SUCCESS
}
