# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/lexoliu/fishbowl/compare/fishbowl-courier-v0.2.1...fishbowl-courier-v0.3.0) - 2026-10-01

### Added

- capture UDP and IPv6 transparently ([#73](https://github.com/lexoliu/fishbowl/pull/73)) ([#74](https://github.com/lexoliu/fishbowl/pull/74))
- give redteam a WARP floor and a per-command Tor leg ([#72](https://github.com/lexoliu/fishbowl/pull/72))
- tier the audit trail between interception and relay ([#71](https://github.com/lexoliu/fishbowl/pull/71))
- fetch and drive a pinned container toolchain
- add a red team mode behind an attestation gate
- *(egress)* route audited traffic over WARP or Tor, with strict modes ([#60](https://github.com/lexoliu/fishbowl/pull/60))

## [0.2.1](https://github.com/lexoliu/fishbowl/compare/fishbowl-courier-v0.2.0...fishbowl-courier-v0.2.1) - 2026-09-30

### Fixed

- ship the workspace README in every published crate ([#58](https://github.com/lexoliu/fishbowl/pull/58))

## [0.2.0](https://github.com/lexoliu/fishbowl/compare/fishbowl-courier-v0.1.1...fishbowl-courier-v0.2.0) - 2026-09-30

### Other

- Forward MALWAREBAZAAR_AUTH_KEY as MALWAREBAZAAR_API_KEY; ship dist artifacts ([#55](https://github.com/lexoliu/fishbowl/pull/55))
