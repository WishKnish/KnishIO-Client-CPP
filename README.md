<div style="text-align:center">
  <img src="https://raw.githubusercontent.com/WishKnish/KnishIO-Technical-Whitepaper/master/KnishIO-Logo.png" alt="Knish.IO: Post-Blockchain Platform" />
</div>
<div style="text-align:center">info@wishknish.com | https://wishknish.com</div>

# Knish.IO C++ Client SDK

This is the official C++ implementation of the Knish.IO client SDK. Its purpose is to expose libraries for building and signing Knish.IO Molecules, composing Atoms, generating Wallets, and interacting with Knish.IO nodes via GraphQL with modern C++20 features, native performance, and quantum-resistant security.

## Installation

The SDK can be built using CMake with the following steps:

### Prerequisites

Ensure you have the following dependencies installed:

- **C++20 compatible compiler** (GCC 10+, Clang 12+, or MSVC 2019+)
- **CMake** 3.20 or higher
- **OpenSSL** 3.0+ for AES-256-GCM (EVP) used by the ML-KEM transport
- **libsodium** 1.0.18+ for cryptographic operations
- **libcurl** 7.0+ for HTTP/GraphQL communication
- **POSIX threads** for concurrent operations

### Platform-Specific Installation

#### macOS (Homebrew)
```bash
brew install cmake pkg-config libsodium openssl@3 curl
```

#### Ubuntu/Debian
```bash
sudo apt-get install cmake pkg-config build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

#### Windows (MSVC)
- Install Visual Studio 2019 or later
- Install vcpkg for dependency management
- Install dependencies: `vcpkg install libsodium openssl curl`

### System dependencies

These libraries are resolved from the **host system** (via `pkg-config` / `find_package`) and are **not** vendored or version-pinned by the build. Because they live outside this repo, their security posture is the responsibility of the host: keep them patched with your platform package manager (`brew upgrade`, `apt upgrade`, etc.).

| Library   | Role                                              | Minimum | Verified on build host |
|-----------|---------------------------------------------------|---------|------------------------|
| OpenSSL   | AES-256-GCM (EVP) for the ML-KEM transport        | 3.0     | 3.6.3                  |
| libcurl   | HTTP / GraphQL transport                          | 7.0     | 8.7.1                  |
| libsodium | SHAKE256 and general cryptographic primitives     | 1.0.18  | 1.0.22                 |

"Verified on build host" is the version this SDK was last built and self-tested against; it is not a ceiling. Newer patch/minor releases are expected to work and should be preferred for security updates.

### Vendored crypto pin

The ML-KEM (FIPS 203) implementation, providing both ML-KEM-768 and ML-KEM-1024, is vendored as a git submodule at `external/mlkem-native`, pinned to **v1.2.0 (`0ba906cb`)** from [pq-code-package/mlkem-native](https://github.com/pq-code-package/mlkem-native). The pin is deliberate so local builds produce byte-identical ML-KEM keys to what CI ships and to the other KnishIO SDKs (cross-SDK crypto parity is asserted by the self-test's ML-KEM-768 and ML-KEM-1024 keygen vectors). The single-header `nlohmann/json` (`src/third_party/nlohmann/json.hpp`, v3.11.3) is likewise vendored. Do not bump either ad hoc — a `git status` showing `M external/mlkem-native` means the submodule has drifted from the pin (`git submodule update --init external/mlkem-native` restores it). Bump the crypto pin only for an upstream security fix, and only after the full self-test still passes byte-identically.

### Build Instructions

1. Clone (with the `external/mlkem-native` submodule) and build the SDK:
   ```bash
   git clone --recursive https://github.com/WishKnish/KnishIO-Client-CPP.git
   cd KnishIO-Client-CPP
   cmake -S . -B build
   cmake --build build --parallel 4
   ```

2. Run tests:
   ```bash
   ctest --test-dir build --output-on-failure
   ```

3. Build examples (on by default; turn off with `-DKNISHIO_BUILD_EXAMPLES=OFF`):
   ```bash
   cmake -S . -B build -DKNISHIO_BUILD_EXAMPLES=ON
   cmake --build build
   ```

4. Install (optional):
   ```bash
   sudo cmake --install build
   ```

5. Use the KnishIO Crypto Core (optional). With `-DKNISHIO_USE_KCORE=ON` the SDK links
   kcore 0.2.0 statically and routes WOTS+ chains, wallet addresses (v1 and v2) and
   ML-KEM-1024/768 through it. Point `CMAKE_PREFIX_PATH` at an extracted
   `knishio-crypto-core-0.2.0-<platform>` package; configure prints
   `kcore: KnishIOCryptoCore 0.2.0`. Inputs kcore does not accept (anything
   but lowercase hex of the exact length) run the SDK's own code, so results are identical.
   ```bash
   cmake -S . -B build -DKNISHIO_USE_KCORE=ON -DCMAKE_PREFIX_PATH=/path/to/knishio-crypto-core-0.2.0-linux-arm64-gnu
   ```

   The prebuilt `knishio-client-cpp-<version>-<platform>.tar.gz` packages on the GitHub Releases
   page are built with kcore (`KNISHIO_USE_KCORE=ON`) and bundle it: `include/kcore.h`,
   `lib/libkcore.*` and `lib/cmake/KnishIOCryptoCore/` sit in the same prefix, with kcore's
   license under `share/licenses/knishio-crypto-core/`, so `find_package(KnishIOClientCPP)`
   resolves kcore without a separate download. Source builds take
   `-DKNISHIO_USE_KCORE=ON -DCMAKE_PREFIX_PATH=<kcore package>`; OFF is still the default.

After installation, link `KnishIO::ClientCPP` (or `KnishIO::ClientCPPStatic`) with
`find_package(KnishIOClientCPP)`, or compile with `-I<prefix>/include -I<prefix>/include/knishio`,
and include the SDK headers:

```cpp
#include <knishio/KnishIOClient.h>       // knishio::KnishIOClient
#include <knishio/Molecule.h>            // KnishIO::Molecule
#include <knishio/Wallet.h>              // KnishIO::Wallet
#include <knishio/Atom.h>                // KnishIO::Atom
#include <knishio/response/Response.h>   // knishio::response::Response*
```

The client lives in namespace `knishio`; the ledger types (`Atom`, `Molecule`, `Wallet`) live in
namespace `KnishIO`.

## Basic Usage

There are two ways to use the SDK:

1. The easy way: the `knishio::KnishIOClient` wrapper, which builds, signs, checks and submits
   molecules for each operation.
2. The granular way: build `KnishIO::Molecule` instances yourself and submit them with
   `KnishIOClient::proposeMolecule`.

Every client operation is asynchronous and returns a `std::future`; call `.get()` for the
response.

## The Easy Way: KnishIOClient Wrapper

1. Build a client for your node:
   ```cpp
   auto client = knishio::KnishIOClient::Builder()
       .uris({"https://node.example/graphql"})
       .cellSlug("my-cell-slug")
       .enableLogging(true)
       .build();
   ```

   Other builder options: `mlKemParameterSet(1024 | 768)`, `otsVersion(2 | 1)`,
   `enableEncryption()`, `insecureTls()`, `timeout(...)`, `maxRetries(...)`.

2. Authenticate with your secret:
   ```cpp
   const std::string secret = knishio::KnishIOClient::generateSecret();   // 2048 random hex characters
   auto auth = client->requestAuthToken(secret).get();
   if (!auth->isAuthorized()) {
       std::cerr << "authorization failed" << std::endl;
   }
   ```

   The secret can be any string: a random hex secret, a hash of login + password + salt, a
   biometric hash, an identifier from another authentication process. `generateSecret(seed)`
   derives a 2048-character secret from a seed deterministically.

3. Use `client` for the operations below.

### KnishIOClient Methods

- Query the balance of a token in your bundle (or another bundle):
  ```cpp
  auto balance = client->queryBalance("CRZY").get();
  if (balance->getBalance()) {
      std::cout << balance->getBalance()->amount << std::endl;
  }
  ```

- Query the wallets of a bundle, optionally for one token:
  ```cpp
  auto wallets = client->queryWallets(std::nullopt, std::string("CRZY")).get();
  for (const auto& wallet : wallets->getWallets()) {
      std::cout << wallet.token << " " << wallet.balance << std::endl;
  }
  ```

- Declare a new wallet (tokens sent to an undeclared wallet land in a shadow wallet, which can
  receive but not send until it is claimed with `claimShadowWallet(token, batchId)`):
  ```cpp
  auto created = client->createWallet("CRZY").get();
  std::cout << (created->isAccepted() ? "accepted" : created->getRejectionReason()) << std::endl;
  ```

- Attach metadata to any (metaType, metaId):
  ```cpp
  auto meta = client->createMeta("Pokemon", "Charizard", {{"type", "fire"}, {"hp", "78"}}).get();
  std::cout << (meta->isAccepted() ? "accepted" : meta->getRejectionReason()) << std::endl;
  ```

- Issue a new token. The meta is hashed in the order given:
  ```cpp
  auto token = client->createToken(
      "CRZY",                                   // token slug
      100000000,                                // initial supply
      {{"name", "CrazyCoin"}, {"fungibility", "fungible"}, {"supply", "limited"}, {"decimals", "0"}}
  ).get();
  std::cout << (token->isCreated() ? "created" : "rejected") << std::endl;

  // A stackable token: the units are the supply; batchId is optional (a fresh one when empty)
  auto stackable = client->createToken("STAK", 0, {{"fungibility", "stackable"}}, "", {"unit-1", "unit-2"}).get();
  ```

- Transfer tokens to another bundle (a batch id makes the recipient a claimable shadow wallet):
  ```cpp
  auto sent = client->transferToken(
      "7bf38257401eb3b0f20cabf5e6cf3f14c76760386473b220d95fa1c38642b61d",   // recipient bundle hash
      "CRZY",                                                                // token slug
      100,                                                                   // amount
      knishio::KnishIOClient::generateSecret(64)                             // batch id
  ).get();
  std::cout << (sent->isAccepted() ? "accepted" : sent->getRejectionReason()) << std::endl;
  ```

  `transferTokens(token, recipients)` funds several recipients in one molecule;
  `burnToken(token, amount)` destroys tokens; `replenishToken(token, amount)` mints more supply of a
  replenishable token; `fuseToken(bundleHash, token, newUnitId, unitIds)` fuses stackable units.

- Buffer tokens:
  ```cpp
  auto deposited = client->depositBufferToken("CRZY", 100, {{"OTHER", "0.5"}}).get();   // trade rates
  auto withdrawn = client->withdrawBufferToken("CRZY", 50).get();
  ```

- Client state:
  ```cpp
  std::cout << client->getBundle() << " " << client->isAuthenticated() << std::endl;
  client->switchEncryption(true);   // ML-KEM encrypted transport for the session
  ```

## The Granular Way: Building Molecules

`createMolecule()` returns a molecule whose source wallet is the USER wallet at your bundle's
live ContinuID position and whose remainder wallet is a fresh USER wallet; fill it with one of
the `Molecule::init*` builders, then submit it. `proposeMolecule` signs the molecule with the
client's secret and takes ownership of it:

```cpp
auto molecule = client->createMolecule();
molecule->initMeta(*molecule->sourceWallet, {{"foo", "Foo"}, {"bar", "Bar"}}, "MyMetaType", "MetaId123");
auto proposed = client->proposeMolecule(molecule.release()).get();
std::cout << (proposed->isAccepted() ? "accepted" : proposed->getRejectionReason()) << std::endl;
```

Building and checking a molecule offline, without a client:

```cpp
KnishIO::Wallet source(secret, "USER", position);    // the USER wallet at your ContinuID position
KnishIO::Wallet remainder(secret, "USER");           // a fresh position
KnishIO::Molecule offline("my-cell-slug");
offline.sourceWallet = std::make_shared<KnishIO::Wallet>(source);
offline.remainderWallet = std::make_shared<KnishIO::Wallet>(remainder);
offline.initMeta(source, {{"foo", "Foo"}}, "MyMetaType", "MetaId123");
offline.sign(secret);

KnishIO::Molecule::check(offline);                     // throws the rule that failed
const bool valid = KnishIO::Molecule::verify(offline); // the same checks, as a bool
std::cout << offline.toJson() << " " << valid << std::endl;
```

`Molecule::verify` and `Molecule::check` apply the JS reference's molecule checks: the molecular
hash, the one-time signature, the ContinuID atom, batch ids, the M/T/C/U/I/R/P/A isotope rules
and value conservation. A molecule served by a validator is verified with
`Molecule::verifyFromServerData(json)`.

## Not implemented

These parts of the JS reference SDK have no C++ counterpart yet:

- Client operations: `queryBundle`, `queryMeta`, `queryMetaVerified`, `queryAtom`, `queryBatch`,
  `queryBatchHistory`, `queryPolicy`, `queryActiveSession`, `queryEmbeddingStatus`,
  `querySourceWallet`, `hasQueryField`, `createRule`, `createPolicy`, `createIdentifier`,
  `linkIdentifier`, `registerPeer`, `appendRequest`, `activeSession`, `requestTokens`,
  `claimShadowWallets`, `requestGuestAuthToken`, `requestProfileAuthToken`, every `subscribe*` /
  `unsubscribe*` operation, and secret-storage integration in the client (the storage providers
  below exist on their own).
- Molecule builders: `createRule`, `addPolicyAtom`, `initIdentifierCreation`, `initPeering`,
  `initAppendRequest`, `initTokenRequest`, `burnToken`, `withParentHashes`.
- Classes: `AtomMeta`, `Meta`, `PolicyMeta`, `AuthToken`, `CheckMolecule` (its checks are
  `Molecule::check` / `Molecule::verify`), `Rule`, `Decimal`, and the per-operation
  `Query*` / `Mutation*` / `Subscribe*` / `Response*` classes other than `QueryBalance` and the
  responses in `response/Response.h`.
- Amounts are whole numbers within ±(2^53 − 1); fractional amounts are not supported.

## Network Freshness

The GraphQL transport (libcurl) issues a fresh network request per query — there
is **no response caching** — so a long-lived client never serves a stale read of
ledger state. No fresh-read knob (e.g. a request policy) is required.

## Secret storage

Master secrets are stored at rest in the cross-SDK AES-256-GCM envelope (PBKDF2-HMAC-SHA256 ×100000, camelCase metadata; frozen in `sdks/shared-test-results/cross-platform-test-vectors.json`). Every SDK decrypts every other SDK's envelope.

| Provider | `providerType` | Custody (`hardwareBacked`) | Where the key lives | Recovery passphrase |
|---|---|---|---|---|
| `MemorySecretStorageProvider` | `memory` | Software (`false`) | Process memory | Optional |
| `AesGcmSecretStorageProvider` | `aes-gcm` | Software (`false`) | Any `StorageBackend` (`MemoryStorageBackend`, `FileStorageBackend` [0600]) | Optional |

`hardwareBacked` is derived by the provider from the platform, never accepted from the caller; software providers always report `false`. A hardware provider refuses to store without a recovery passphrase unless `allowUnrecoverable` is set — the recovery envelope (`knishio:recovery:<bundleHash>`, `providerType: "aes-gcm"`) is *software* custody whose strength is bounded by that passphrase: enforce passphrase entropy or keep it on a second device.

## Thread safety

A KnishIOClient instance is not thread-safe; use one instance per thread or guard a shared instance with a mutex. Wallet and Molecule signing/verification on separate objects are thread-safe.

Everything runs on the calling thread (kcore starts no threads of its own), so for multi-core throughput sign or verify independent molecules on separate threads.

## Getting Help

Knish.IO is under active development, and our team is ready to assist with integration questions. The best way to seek help is to stop by our [Telegram Support Channel](https://t.me/wishknish). You can also [send us a contact request](https://knish.io/contact) via our website.
