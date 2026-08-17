# Changelog

All notable changes to the KnishIO Client C++ SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
This SDK has **no package registry**: it is distributed as source, and a release
is a git tag (`CMakeLists.txt` `project(... VERSION ...)` is the version of
record). GitHub Releases are being set up separately.
Conventions for tags, commits, and these entries: `docs/SDK-RELEASE-CONVENTIONS.md`
in the KnishIOClientSDK monorepo.

This file was backfilled on 2026-07-27 from the repository's own tag and commit
history rather than written at release time; where the history does not
substantiate a detail, the entry says so instead of guessing.

## [0.9.4] — 2026-08-17

### Security

- **ML-KEM-768 encapsulation now draws its randomness from the platform CSPRNG.** It
  previously used the mlkem-native *test* RNG stub (`external/mlkem-native/test/notrandombytes/notrandombytes.c`,
  a SURF PRNG seeded with a compile-time constant — the digits of π), which was compiled
  into the shipped library and supplied the only `randombytes()` in the link. Because ML-KEM
  derandomizes K-PKE (`r = G(m ‖ H(ek))`), the 32-byte message `m` is the sole entropy in an
  encapsulation — so every process replayed the same sequence of ciphertexts and shared
  secrets, making the AES-256-GCM key of any *sent* message recoverable by an attacker.
  `src/Wallet.cpp` (`encryptMessageML768`) now generates `m` with OpenSSL `RAND_bytes` and
  calls the derandomized `crypto_kem_enc_derand`; `MLK_CONFIG_NO_RANDOMIZED_API` compiles out
  the randomized path (and the stub) entirely, and `notrandombytes.c` is removed from the
  build. Decapsulation, key generation, and cross-SDK parity are byte-unchanged (self-test
  10/10, Cross-SDK ✅, 6 frozen molecular hashes intact). A new cross-process determinism test
  (`tests/mlkem_encaps_entropy.cpp`, CTest `MlkemEncapsEntropy`) fails on the old behavior and
  passes on the fix.

## [0.9.3] — 2026-08-05

### Added

- Classical NaCl cross-platform parity vectors asserted in the test suite.

### Changed — cross-SDK gauntlet reporting integrity

- The self-test now publishes cross-validation **coverage**, not just a verdict:
  `crossValidation.{ran,targetsExpected,targetsValidated}` and `runId` sit alongside
  `crossSdkCompatible` in the results file. The boolean alone could not distinguish
  "validated every peer, all passed" from "validated nothing and so found no failures".
- `crossSdkCompatible` now defaults to **false** and must be earned. It was `true`, so every early return out of cross-validation published a pass.
- Cross-validation **fails** instead of reporting "compatible" when the shared results
  directory is missing or holds no peer results. Absence of evidence is not evidence of
  compatibility.
- Round 1 no longer asserts a cross-SDK verdict it cannot have; it records that no
  cross-validation ran.
- A coverage floor is required before a pass: every expected peer must have been validated,
  in addition to no individual check having failed.
- Each peer is now checked for all 7 required molecule types. The validation loop iterates
  the molecule keys that are **present**, so an omitted molecule was indistinguishable from
  a validated one.
- The Round-2 molecule preserve-block gains a drift guard. It is itemized, and in
  Round-2-only mode it is the sole source of the molecules this SDK republishes, so a
  type missing from it is republished empty and destroys Round 1's work.

Contract for these fields: `sdks/canonical-test-keys.json` in the KnishIOClientSDK
monorepo. Audit: `docs/audits/REPORTING-INTEGRITY-2026-08-05.md`.

## [0.9.2] — 2026-07-12

Coordinated dependency-security release across all 8 SDKs. Release record:
`docs/sdk-release-0.9.2-execution-2026-07-12.md` (monorepo).

### Security

- `mlkem-native` bumped to v1.2.0, picking up upstream zeroization and an
  x86-64 assembly overread fix.

### Changed

- `nlohmann/json` bumped to 3.11.3.
- `SDK_VERSION` constants bumped alongside the CMake project version.

### Fixed

- Round-2 self-test results are preserved rather than clobbered, which had made
  cross-SDK validation flaky when rounds ran in parallel.

### Notes

- `0.9.1` was staged in `CMakeLists.txt` on 2026-06-30 (an actionable message for
  the ML-KEM key-size guard) but was never tagged. That change ships in `0.9.2`.

## [0.9.0] — 2026-06-29

Coordinated `0.9.0` across all 8 SDKs, marking the post-quantum ML-KEM transport
milestone. Runbook: `docs/sdk-release-audit-2026-06-29.md` (monorepo).

### Added

- **ML-KEM768 CipherHash encrypted transport** (PQ Phase E), backed by
  `mlkem-native` vendored as a git submodule at `external/mlkem-native` — clone
  with `--recursive`.
- Live wiring of the whole client: `GraphQLClient` transport with TLS and
  `X-Auth-Token`, `initAuthorization` / `requestAuthToken` → live JWT,
  `proposeMolecule`, `createToken`, `createWallet`, `claimShadowWallet`, and
  batched/shadow `transferToken` — all accepted by a live validator.
- Stackable (NFT) support: `TokenUnit`, `Wallet::splitUnits`, `tokenUnits`
  emission on `initValue` and in `createToken`, `tokenUnits` exposed on
  `queryBalance`, and a multi-recipient stackable transfer builder.
- `burnToken` as a canonical 3-V-atom zero-sum molecule.
- Buffer family: builders, the `isotopeV` bypass, and client wrappers, with
  `testBufferFamily` driven off `canonical-patent-vectors.json`.
- `tokenCreation`, `walletCreation`, and `shadowWalletClaim` cross-SDK parity
  (7/8 each), plus the `mlkem768` keygen + decrypt vector and a "decrypt their
  message" ML-KEM768 cross-validation.
- A clang-tidy lint gate (`bugprone-*` / `performance-*`, warnings-as-errors) and
  the repo's first CI workflow — build, self-test, and lint, born-enforced.

### Changed

- AES-256-GCM migrated from libsodium to the OpenSSL EVP interface: portable, and
  no longer gated on AES-NI.
- The classical NaCl path is documented as non-PQ in `crypto.cpp` / `crypto.h`.

### Fixed

- The build now produces a real shared `.dylib` (the `SHARED` keyword had been
  omitted).
- SHAKE256 empty-input handling, and correction of bogus test vectors (14/14).
- Response getters corrected to the actual `ProposeMolecule` payload shapes.
- Missing `<cstdint>`, `<cstring>`, and `<optional>` includes.
- Debug output on stderr stripped from library code.

### Notes

- Local version `0.8.1` was staged on 2026-06-15 (the tokenCreation /
  walletCreation / shadowWalletClaim parity work) but was never tagged; it
  reaches consumers here.

## [0.8.0] — 2026-06-14

First release of the modern C++ SDK line. The manifest had carried `1.0.0` since
the 2025-10-08 omnibus catch-up commit; it was set **down** to `0.8.0` to join the
coordinated SDK version line, which is the honest description of the SDK's
maturity at that point.

### Fixed

- Molecule construction and the ML-KEM seed reconciled to the JS reference,
  bringing the C++ SDK into 4-SDK parity.

## Earlier releases

`0.1.37` (2019) predates this SDK's modern line entirely. See the git history.

[Unreleased]: https://github.com/WishKnish/KnishIO-Client-CPP/compare/0.9.4...HEAD
[0.9.4]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.4
[0.9.3]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.3
[0.9.2]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.2
[0.9.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.0
[0.8.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.8.0
