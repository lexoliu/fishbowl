#!/bin/sh
# Builds fishbowl, signs it with one of your own certificates, and installs it.
#
# The signature is what keeps macOS from asking for your password every time. The host
# reads your Claude Code login out of the Keychain to lend the session a token, and the
# Keychain lets an application do that without asking only once you have answered
# "Always Allow" for it — an answer it remembers by the application's signed identity. A
# binary straight out of cargo carries only the linker's ad-hoc signature, which is a new
# identity on every build, so every rebuild is a stranger and asks again. Signed with the
# same certificate under the same identifier, every build is the one you already allowed.
#
#   FISHBOWL_SIGNING_IDENTITY="Apple Development: You (TEAMID)" scripts/install.sh
#
# `security find-identity -v -p codesigning` lists the certificates you can sign with. An
# Apple Development certificate is enough; nothing here is notarised or distributed.
set -eu

identifier="cool.lexo.fishbowl"
destination="${FISHBOWL_INSTALL_DIR:-$HOME/.local/bin}"
workspace="$(cd "$(dirname "$0")/.." && pwd)"

identity="${FISHBOWL_SIGNING_IDENTITY:-}"
if [ -z "$identity" ]; then
  echo "scripts/install.sh: set FISHBOWL_SIGNING_IDENTITY to one of these:" >&2
  security find-identity -v -p codesigning >&2
  exit 64
fi

cargo build --release --manifest-path "$workspace/Cargo.toml" -p fishbowl
binary="$workspace/target/release/fishbowl"

# `--force` replaces the linker's ad-hoc signature; the identifier is fixed so that the
# Keychain's memory of the application survives a rename of the build directory too.
codesign --force --sign "$identity" --identifier "$identifier" "$binary"
codesign --verify --strict "$binary"

mkdir -p "$destination"
install -m 0755 "$binary" "$destination/fishbowl"
echo "installed $destination/fishbowl, signed as \"$identity\""
