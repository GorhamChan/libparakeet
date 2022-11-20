# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- New API - `parakeet_crypto::get_libparakeet_full_version` for full library version, including commit date and hash.

## [0.2.1] - 2022-11-13

### Changed

- Improved Kuwo `kwm` support for files with an alternate header magic values.

## [0.2.0] - 2022-11-13

### Added

- Source import from [parakeet-wx]

- Re-implement the support for Kugou `kgm` / `vpr` format.
  - Support for Kugou `kgm` / `vpr` files.
  - Support for KuWo `kwm` files.
  - Support for Netease `ncm` files.
  - Support for QMCv1 and partial support for QMCv2 files.
  - Support for Xiami `xm` files.
  - Support for Joox `ofl_en` files.
  - Support for Ximalaya `x2m` / `x3m` files.
  - Audio type detection via file header.

[parakeet-wx]: https://github.com/parakeet-rs/parakeet-wx
[0.2.0]: https://github.com/parakeet-rs/libparakeet/commits/v0.2.0
[0.2.1]: https://github.com/parakeet-rs/libparakeet/compare/v0.2.0...v0.2.1
