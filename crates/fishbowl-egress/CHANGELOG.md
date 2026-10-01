# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/lexoliu/fishbowl/compare/fishbowl-egress-v0.2.1...fishbowl-egress-v0.3.0) - 2026-10-01

### Added

- capture UDP and IPv6 transparently ([#73](https://github.com/lexoliu/fishbowl/pull/73)) ([#74](https://github.com/lexoliu/fishbowl/pull/74))
- give redteam a WARP floor and a per-command Tor leg ([#72](https://github.com/lexoliu/fishbowl/pull/72))
- tier the audit trail between interception and relay ([#71](https://github.com/lexoliu/fishbowl/pull/71))
- fetch and drive a pinned container toolchain
- add a red team mode behind an attestation gate
- *(egress)* route audited traffic over WARP or Tor, with strict modes ([#60](https://github.com/lexoliu/fishbowl/pull/60))
- give the researcher account root, keep the filter out of its reach ([#44](https://github.com/lexoliu/fishbowl/pull/44))
- brief agents on the machine, and cut detonated samples off the network ([#43](https://github.com/lexoliu/fishbowl/pull/43))
- publish the sandbox image instead of building it per machine ([#39](https://github.com/lexoliu/fishbowl/pull/39))
- run Devin inside a session on its lent credentials file ([#34](https://github.com/lexoliu/fishbowl/pull/34))
- sign the installed binary so the keychain asks once
- name the image for the sources it was built from
- detonate samples under an account that owns nothing
- run claude code in a session on a token lent from the host
- open a session with codex driving it
- [**breaking**] replace the sandbox lifecycle commands with sessions
- isolated audited security-research sandboxes on macOS

### Fixed

- get the published image and its waiting room working ([#40](https://github.com/lexoliu/fishbowl/pull/40))
- switch codex's hooks off for the run instead of asking about them
- keep the transport out of the user's vocabulary

### Other

- Merge pull request #69 from lexoliu/feat/68-managed-container-toolchain
- Forward MALWAREBAZAAR_AUTH_KEY as MALWAREBAZAAR_API_KEY; ship dist artifacts ([#55](https://github.com/lexoliu/fishbowl/pull/55))
- Reclaim sessions once the sandbox store outgrows its cap ([#51](https://github.com/lexoliu/fishbowl/pull/51))
- rename the project to fishbowl ([#38](https://github.com/lexoliu/fishbowl/pull/38))
- Merge pull request #29 from lexoliu/feat/signed-install
