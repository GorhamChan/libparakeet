# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.3] - 2023-12-24

### Added

- Add support for `musicex` tail tag (QMPC)

## [0.7.2] - 2023-12-21

### Added

- Add `utils::UnHex` method.

## [0.7.1] - 2023-12-21

### Changed

- Expose `qtfm::CreateDeviceSecretKey` method.

## [0.7.0] - 2023-11-28

### Added

- Support for QingTingFM (`.qta`) files.
- Added CTR mode for AES encryption/decryption.

### Changed

- Refactored AES code base with templates.

## [0.6.5] - 2023-11-17

### Changed

- Remove use of `sprintf` from the code base.

## [0.6.4] - 2023-11-17

### Changed

- Expose `base64` and `tc_tea` methods.

## [0.6.3] - 2023-10-11

### Changed

- Improved `QMC2DecryptionTransformer` allowing user to override with a specific key.

## [0.6.2] - 2023-07-16

### Changed

- Fixed QRC decode - it should not report error in the end.
- Removed Crypto++ dependency.

## [0.6.1] - 2023-06-17

### Changed

- Fixed `SlicedReadableStream` read/seek behaviour at start boundary.
- Fixed kuwo parser to use `uint32_t` for `resource_id`.

## [0.6.0] - 2023-06-17

### Added

- Support KWMv2 (via QMCv2) with custom ekey.

## [0.5.0] - 2023-05-27

### Added

- Support for QRC Lyrics decryption.
- Support for Migu3D decryption (key & keyless).

### Changed

- Documented kuwo's crypto_version field.
- Target CMake 3.22.1 with preset version 3 (was 5)

## [0.4.1] - 2022-02-20

### Changed

- QMC2: Fixed a bug in segment key generation.

## [0.4.0] - 2022-02-13

### Added

- QMC2: Expose constant `kEncV2KeyLen`.
- QMC2: Added a helper transformer that can handle both QMC2(MAP) & QMC2(RC4).
- XMLY: Added helper function `CreateScrambleKey`.
- MISC: Logger that can be disabled using CMAKE options `PARAKEET_CRYPTO_LOGGING_ENABLE_WARN` and
        `PARAKEET_CRYPTO_LOGGING_ENABLE_ERROR`.
- MISC: Various helper functions that takes container template.

### Changed

- KGM: Broken `vpr` implementation (mode selection)
- NCM: Check for header and exit early
- KUWO: non-reusable decryption transformer (key initialisation)
- XIAMI: Fixed key derivation

## [0.3.0] - 2022-02-11

### Added

- `ITransformer` interface for transformation.
- Test file for all transformer implemented.

### Changed

- (breaking) Interface changes
  - dropped old `StreamDecryptor` interface, infavour of redesigned `ITransformer`.
- Reduced C++ standard from C++20 to C++17 for better tooling support.
- Fixed KGM-Type4 implementaion discovered during refactoring.

### Removed

- Removed `DecryptorManager`. You should implement your own.
- Removed audio type detection, use [libparakeet-audio] instead.

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
[libparakeet-audio]: https://github.com/parakeet-rs/libparakeet-audio
[0.2.0]: https://github.com/parakeet-rs/libparakeet/commits/v0.2.0
[0.2.1]: https://github.com/parakeet-rs/libparakeet/compare/v0.2.0...v0.2.1
[0.3.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.2.1...v0.3.0
[0.4.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.3.0...v0.4.0
[0.4.1]: https://github.com/parakeet-rs/libparakeet/compare/v0.4.0...v0.4.1
[0.5.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.4.1...v0.5.0
[0.6.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.5.0...v0.6.0
[0.6.1]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.0...v0.6.1
[0.6.2]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.1...v0.6.2
[0.6.3]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.2...v0.6.3
[0.6.4]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.3...v0.6.4
[0.6.5]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.4...v0.6.5
[0.7.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.6.5...v0.7.0
[0.7.1]: https://github.com/parakeet-rs/libparakeet/compare/v0.7.0...v0.7.1
[0.7.2]: https://github.com/parakeet-rs/libparakeet/compare/v0.7.1...v0.7.2
[0.7.3]: https://github.com/parakeet-rs/libparakeet/compare/v0.7.2...v0.7.3
[0.x.0]: https://github.com/parakeet-rs/libparakeet/compare/v0.7.3...v0.x.0
