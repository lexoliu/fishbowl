# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/lexoliu/fishbowl/compare/fishbowl-v0.2.1...fishbowl-v0.3.0) - 2026-10-01

### Added

- capture UDP and IPv6 transparently ([#73](https://github.com/lexoliu/fishbowl/pull/73)) ([#74](https://github.com/lexoliu/fishbowl/pull/74))
- give redteam a WARP floor and a per-command Tor leg ([#72](https://github.com/lexoliu/fishbowl/pull/72))
- tier the audit trail between interception and relay ([#71](https://github.com/lexoliu/fishbowl/pull/71))
- fetch and drive a pinned container toolchain
- add a red team mode behind an attestation gate
- *(egress)* route audited traffic over WARP or Tor, with strict modes ([#60](https://github.com/lexoliu/fishbowl/pull/60))

### Fixed

- parse container 1.5's nested system status
- satisfy clippy's items-after-statements and enum-glob-use
- start the runtime's services when the status probe itself fails

### Other

- Merge pull request #69 from lexoliu/feat/68-managed-container-toolchain
- swap the sprite for the classic defacement skull
- redraw the attestation skull as a pixel sprite
- centre the skull frame, sentence-case the warning

## [0.2.1](https://github.com/lexoliu/fishbowl/compare/fishbowl-v0.2.0...fishbowl-v0.2.1) - 2026-09-30

### Fixed

- ship the workspace README in every published crate ([#58](https://github.com/lexoliu/fishbowl/pull/58))

## [0.2.0](https://github.com/lexoliu/fishbowl/compare/fishbowl-v0.1.1...fishbowl-v0.2.0) - 2026-09-30

### Other

- Forward MALWAREBAZAAR_AUTH_KEY as MALWAREBAZAAR_API_KEY; ship dist artifacts ([#55](https://github.com/lexoliu/fishbowl/pull/55))
- Reclaim sessions once the sandbox store outgrows its cap ([#51](https://github.com/lexoliu/fishbowl/pull/51))

## [0.1.1](https://github.com/lexoliu/fishbowl/compare/fishbowl-v0.1.0...fishbowl-v0.1.1) - 2026-09-12

### Added

- give the researcher account root, keep the filter out of its reach ([#44](https://github.com/lexoliu/fishbowl/pull/44))
- brief agents on the machine, and cut detonated samples off the network ([#43](https://github.com/lexoliu/fishbowl/pull/43))

### Fixed

- get the published image and its waiting room working ([#40](https://github.com/lexoliu/fishbowl/pull/40))
