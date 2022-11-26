# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.4] - 2022-11-27

### Changed

- (breaking) `parakeet_crypto::utils::Unhex` renamed to `parakeet_crypto::utils::UnHex`.
- Make utils functions to take `std::span<uint8_t>` instead of `std::vector` / `std::string`, with wrappers to provide
  backward compatibility.

## [0.2.3] - 2022-11-22

### Changed

- Fix assertion macro when generating Ximalaya X2M/X3M table using parameters.

## [0.2.2] - 2022-11-22

### Added

- New API - `parakeet_crypto::get_libparakeet_full_version` for full library version, including commit date and hash.
- Ximalaya - New API to generate scramble table on-the-fly by using `init` and `step` parameters.

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
