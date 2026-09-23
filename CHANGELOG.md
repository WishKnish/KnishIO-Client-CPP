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

## [1.2.1] — 2026-09-23

### Changed

- `Molecule::sign(secret, anonymous = false, compressed = true)` base64-compresses the 2048-hex
  one-time signature to 1368 characters before splitting it across the atoms, as every other
  SDK's 1.2.x does. Existing two-argument calls compile unchanged.
- `Molecule::enumerate()` and `Molecule::normalize()` return `std::vector<int8_t>` instead of
  `std::vector<char>`; code that names the element type switches to `int8_t` or `auto`. These
  installed-header changes ship in a patch release to keep the C++ SDK in step with the fleet's
  1.2.x.

### Fixed

- Signatures are byte-identical to the other seven SDKs': 684 + 684 base64 characters on the
  frozen `wotsSignedMetadataMolecule` vector, where 1.2.0 emitted 1024 + 1024 hex characters that
  no other SDK accepts.
- Where plain `char` is unsigned (aarch64), `enumerate()` and `normalize()` turned the −8..8 hash
  symbols into 248..255, so no verifier accepted a signature made there, this SDK's own included.
- Splitting the 2048-character signature across n atoms used `std::round` for the chunk size,
  which produced more chunks than atoms whenever `ceil(2048 / round(2048 / n)) > n`; the extra
  chunks were written past the end of the atom list (undefined behaviour). Up to 64 atoms that
  happens at 21 sizes: 6, 11, 14, 17, 20, 22, 23, 24, 28, 30, 31, 33, 34, 37, 40, 51, 52, 55, 58,
  60 and 62. It now uses integer ceiling division, as the JS reference and the C SDK do.
- `Molecule::verifyOts()` base64-decodes a signature that is not 2048 hex characters and rejects
  one that does not decode to 2048, the JS reference rule; 1.2.0's rejected every compressed
  signature, that is, every other SDK's. It also honours a `signingWallet` address in atoms[0]'s
  meta, as the JS reference and the Rust validator do.
- The SDK builds on Linux with libstdc++ (missing `<memory>` and `<cmath>` includes, and
  `std::fabsl`).
- `normalize()`'s documentation no longer claims the scheme reveals exactly half the key.

### Security

- In 1.2.0 and earlier `Molecule::verify()` did not check the one-time signature, so a molecule
  with a forged or corrupted signature passed it; `KnishIOClient` uses it as its pre-send check.
  It now requires a valid one-time signature.

### Notes

- CI and the publish workflow now run `ctest`. Until this release they built the unit tests
  without running them, so `WotsSignatureParity` (the regression test for the signature fixes
  above), `LegacyMlkem768Compat` and the other ctest entries ran only locally. `CipherHashLive`
  reports Skipped, not Passed, when `CIPHERHASH_TEST_URL` is unset.
- Evidence: the aarch64 edge-kit rig (stock Ubuntu 22.04, no network). In its round 2 all seven
  other SDKs accept this SDK's molecules; in its round 3 this SDK rejects all seven peers'
  molecules whose signature had one character changed.

## [1.2.0] — 2026-09-20

### Added

- `http::EncryptedTransportException` (derives `GraphQLException`) in
  `include/http/GraphQLClient.h`.

### Changed

- `http::GraphQLClient` **fails closed**: `EncryptedTransportException("Authorized wallet
  missing.")` / `("Server public key missing.")` instead of sending the request in plaintext, with
  the bypass set decided first. The retry loop and `KnishIOClient` rethrow it immediately — no
  amount of retrying supplies a missing key.

### Notes

- Both live CipherHash cases (`tests/cipherhash_live_test.cpp`) passed against
  `testnet.knish.io` on 2026-09-20 at ML-KEM-1024 and ML-KEM-768, including the validator
  refusing a plaintext query from an `encrypt=true` session.

## [1.1.0] — 2026-09-12

### Added

- **Hardware-compatible envelope secret storage layer** (`knishio::storage`, `KnishIO::storage`) adhering to the cross-SDK envelope specification:
  - `SecretEnvelope`: AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation (100,000 iterations, 16-byte random salt, 12-byte random IV, 16-byte authentication tag appended to ciphertext, standard padded Base64 encoding).
  - Cross-SDK `SecretStorageMetadata` wire format with required camelCase keys (`bundleHash`, `createdAt`, `hardwareBacked`, `providerType`) and optional `label` (omitted when empty, never null). Deserialization tolerates legacy `snake_case` keys for backwards compatibility.
  - `SecretStorageProvider` interface with `AesGcmSecretStorageProvider` (software envelope encryption) and `MemorySecretStorageProvider` (in-memory provider for testing).
  - `StorageBackend` pluggable persistence interface with `MemoryStorageBackend` and `FileStorageBackend` (atomic write via temporary file + rename, 0600 restrictive file permissions).
  - `SecureMemory`: RAII wrappers (`SecureBytes`, `SecureString`), scoped helpers (`withSecureBytes`, `withSecureString`), buffer zeroization (`zeroizeBytes`, `zeroizeString`), and constant-time comparisons (`constantTimeEquals`).
  - `SecretStorageException` with typed factory methods (`notFound`, `decryptionFailed`, `unavailable`).
  - Comprehensive unit and cross-platform vector test suite (`test_secret_storage`) verifying frozen TypeScript envelope decryption (`cross-sdk-pass` -> `MASTER-SECRET-CROSS-SDK-PROBE`), camelCase metadata key enforcement, round trip, wrong passphrase rejection, and corruption detection.
  - Secret recovery contract support (`RECOVERY_KEY_PREFIX = "knishio:recovery:"`):
    - Extended `StorageOptions` with `recoveryPassphrase` (`std::optional<std::string>`) and `allowUnrecoverable` (`bool`, default `false`).
    - Added `recoverSecret(bundleHash, recoveryPassphrase, options)` to `SecretStorageProvider` interface.
    - In `AesGcmSecretStorageProvider` and `MemorySecretStorageProvider`: dual-sealing of secondary recovery envelope under `recoveryPassphrase` (`providerType: "aes-gcm"`, `hardwareBacked: false`) to `knishio:recovery:<bundleHash>`, atomic deletion of both primary and recovery keys in `deleteSecret`, exclusion of recovery keys from `listSecrets()`, and zero-leak re-enrollment in `recoverSecret()`.
    - Comprehensive recovery unit tests in `test_secret_storage` covering primary/recovery storage, list filtering, primary loss simulation, fail-closed bad-passphrase rejection, byte-identical restoration under fresh ciphertext, and cascade deletion.

## [1.0.0] — 2026-09-10

### Added

- A wallet now decrypts records addressed to **its own ML-KEM-768 identity even when configured at
  ML-KEM-1024**, by deriving that identity on demand from the same 64-byte wallet seed. The seed is
  parameter-set-independent, so both identities belong to one wallet; only the final
  `keypair_derand` call differs. Reading pre-bump 768 records therefore needs no configuration
  change and no second wallet. `Wallet::mlkemDecryptToString()` dispatches on the decoded
  ciphertext's length (1088 → ML-KEM-768, 1568 → ML-KEM-1024) and the derived private key is
  zeroized when it leaves the decrypting scope — it is never cached on the wallet.
- `Wallet::decryptMyMessageML()` tries both identities' `CipherHash` map keys, so a `CipherHash`
  envelope a pre-bump peer addressed to `hashShare(our_768_pubkey)` is found rather than missed.

  Encapsulation and the advertised public key are unchanged and remain single-set: inbound is
  permissive, outbound is strict. Reading a 768 record you own downgrades nothing — its
  confidentiality was fixed at 768 by the sender — whereas permissive outbound would be a real
  downgrade vector.

### Changed

- **ML-KEM-1024 is the default parameter set** for the post-quantum transport, replacing
  ML-KEM-768. `Wallet`'s fifth constructor argument (`mlkemParameterSet`) and
  `KnishIOClient::Builder::mlKemParameterSet()` select it (`1024` default, `768` step-back).
- `Wallet::encryptMessageML()` is strict and **throws** `std::invalid_argument` on a wrong-length
  recipient key rather than silently downgrading to whatever the peer advertised.

### Removed

- The four backward-compatibility shims on `Wallet`: `encryptMessageML768()`,
  `decryptMessageML768()`, `encryptStringML768()` and `decryptMyMessageML768()`. Use
  `encryptMessageML()`, `decryptMessageML()`, `encryptStringML()` and `decryptMyMessageML()`. No
  aliases are retained.

### Fixed

- The self-test's cross-SDK validation result is counted in the exit-code tally. `total_tests` was
  12 while the tally summed eleven booleans, so the binary printed success and exited 0 even when
  every peer molecule failed to validate or decrypt.
- The self-test's default shared-results directory is `../shared-test-results`, one level lower
  than the previous `../../shared-test-results`, so it now matches the SDK-root-relative
  convention the fixture lookups in the same file already use. The orchestrated cross-SDK run
  overrides this with `KNISHIO_SHARED_RESULTS` and is unaffected either way; the default matters
  only for a standalone run, which resolves it against the process working directory.
- `Wallet::mlkemDecryptToString()` verifies the length of the ML-KEM private key before
  decapsulating. `mlkem768_dec`/`mlkem1024_dec` read 2,400/3,168 bytes from the pointer they are
  given, and the secret key was passed unchecked, so a wallet constructed without a secret — which
  leaves the key vector empty — caused an out-of-bounds read off a zero-length buffer rather than a
  clean failure. Both the configured-parameter-set path (pre-existing) and the new sibling-identity
  path now throw `std::invalid_argument` instead.

### Notes

- The ML-KEM-1024 cutover is a breaking API change, so it takes the 1.0.0 line.
- **Session-snapshot parameter-set persistence does not apply to this SDK.** The sibling SDKs gained
  it in this release; C++ has no `AuthToken` at all — `class AuthToken;` is forward-declared in
  `src/KnishIOClient.h` and never defined, and `KnishIOClient` holds the JWT as
  `std::optional<std::string>`. There is no snapshot to carry a parameter set.
- A frozen pre-bump ML-KEM-768 auth molecule (`vectors.legacyMlkem768AuthMolecule` in
  `cross-platform-test-vectors.json`) is validated by this SDK from a 1024-default build
  (`tests/legacy_mlkem768_compat.cpp`, CTest `LegacyMlkem768Compat`), so the compatibility claim
  rests on a signed artifact rather than on parameter-set-independent hashing. That leg covers
  `Molecule::verify()` — molecular hash plus isotope-V conservation. `Molecule::verify()`
  deliberately does not call `verifyOts()`, which needs the sender's wallet and is not wired in;
  this release does not change that.

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

[Unreleased]: https://github.com/WishKnish/KnishIO-Client-CPP/compare/1.2.1...HEAD
[1.2.1]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/1.2.1
[1.2.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/1.2.0
[1.1.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/1.1.0
[1.0.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/1.0.0
[0.9.4]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.4
[0.9.3]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.3
[0.9.2]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.2
[0.9.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.9.0
[0.8.0]: https://github.com/WishKnish/KnishIO-Client-CPP/releases/tag/0.8.0
