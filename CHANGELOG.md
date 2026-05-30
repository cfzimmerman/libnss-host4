# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/cfzimmerman/libnss-host4/releases/tag/v0.2.0)

First polished release.

### Changed

- **Breaking:** `Addr` is now a struct instead of an enum.
- **Breaking:** Panic handling means this crate is no longer `no_std`.

### Added

- Any panics in user code are stopped with `std::panic::catch_unwind` before
  crossing FFI. These errors are reported as NSS `Unavailable`.
- Docs, tests, crates.io metadata, and license files.

## [0.1.0](https://github.com/cfzimmerman/libnss-host4/commit/869d58195a1bca83ac0f3c0d26f331b83a1500d6)

Initial release to reserve the crate name.
