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
- **libsodium** 1.0.18+ for cryptographic operations
- **libcurl** 7.0+ for HTTP/GraphQL communication
- **POSIX threads** for concurrent operations

### Platform-Specific Installation

#### macOS (Homebrew)
```bash
brew install cmake libsodium curl
```

#### Ubuntu/Debian
```bash
sudo apt-get install cmake libsodium-dev libcurl4-openssl-dev build-essential
```

#### Windows (MSVC)
- Install Visual Studio 2019 or later
- Install vcpkg for dependency management
- Install dependencies: `vcpkg install libsodium curl`

### Build Instructions

1. Clone and build the SDK:
   ```bash
   git clone https://github.com/WishKnish/KnishIO-Client-CPP.git
   cd KnishIO-Client-CPP
   mkdir build && cd build
   cmake ..
   cmake --build . --parallel 4
   ```

2. Run tests:
   ```bash
   ctest
   ```

3. Build examples (optional):
   ```bash
   cmake -DKNISHIO_BUILD_EXAMPLES=ON ..
   cmake --build .
   ```

4. Install system-wide (optional):
   ```bash
   sudo make install
   ```

After installation, include the SDK in your project:

```cpp
#include <knishio/KnishIOClient.h>
#include <knishio/Molecule.h>
#include <knishio/Wallet.h>
#include <knishio/Atom.h>
```

## Basic Usage

The purpose of the Knish.IO SDK is to expose various ledger functions to new or existing applications.

There are two ways to take advantage of these functions:

1. The easy way: use the `KnishIOClient` wrapper class with builder pattern

2. The granular way: build `Atom` and `Molecule` instances and broadcast GraphQL messages yourself

This document will explain both ways.

## The Easy Way: KnishIOClient Wrapper

1. Include the wrapper class in your application code:
   ```cpp
   #include <knishio/KnishIOClient.h>
   ```

2. Instantiate the client with your node URI using the builder pattern:
   ```cpp
   auto client = knishio::KnishIOClient::Builder()
       .uris({"https://api.knishio.dev", "https://backup.knishio.dev"})
       .cellSlug("my-cell-slug")
       .enableLogging(true)
       .build();
   ```

3. Set your secret for authentication:
   ```cpp
   // Generate a secret
   std::string secret = knishio::KnishIOClient::generateSecret(2048);

   // Set the secret for the client
   client->setSecret(secret);

   // Note: C++ SDK uses stored secret for cryptographic operations
   // This is equivalent to the JavaScript SDK's await client.requestAuthToken()
   ```

   (**Note:** The `secret` parameter can be a salted combination of username + password, a biometric hash, an existing user identifier from an external authentication process, for example)

4. Begin using `client` to trigger commands described below...

### KnishIOClient Methods

- Query metadata for a **Wallet Bundle**. Omit the `bundleHash` parameter to query your own Wallet Bundle:
  ```cpp
  auto response = client->queryBundle(
      "c47e20f99df190e418f0cc5ddfa2791e9ccc4eb297cfa21bd317dc0f98313b1d"
  );

  if (response.success()) {
      std::cout << response.data() << std::endl; // Raw Metadata
  }
  ```

- Query metadata for a **Meta Asset**:

  ```cpp
  auto result = client->queryMeta(
      "Vehicle",      // metaType
      "CAR123",       // metaId
      "LicensePlate", // key
      "1H17P",        // value
      true            // latest
  );

  std::cout << result << std::endl; // Raw Metadata
  ```

- Writing new metadata for a **Meta Asset**:

  ```cpp
  std::map<std::string, std::string> metadata = {
      {"type", "fire"},
      {"weaknesses", "rock,water,electric"},
      {"immunities", "ground"},
      {"hp", "78"},
      {"attack", "84"}
  };

  auto response = client->createMeta(
      "Pokemon",      // metaType
      "Charizard",    // metaId
      metadata
  );

  if (response.success()) {
      std::cout << "Metadata created successfully!" << std::endl;
  }

  std::cout << response.data() << std::endl; // Raw response
  ```

- Query Wallets associated with a Wallet Bundle:

  ```cpp
  auto wallets = client->queryWallets(
      "c47e20f99df190e418f0cc5ddfa2791e9ccc4eb297cfa21bd317dc0f98313b1d", // bundleHash
      "FOO",  // token (optional)
      true    // unspent
  );

  std::cout << wallets << std::endl; // Raw response
  ```

- Declaring new **Wallets**:

  (**Note:** If Tokens are sent to undeclared Wallets, **Shadow Wallets** will be used (placeholder
  Wallets that can receive, but cannot send) to store tokens until they are claimed.)

  ```cpp
  auto response = client->createWallet("FOO"); // Token Slug for the wallet we are declaring

  if (response.success()) {
      std::cout << "Wallet created successfully!" << std::endl;
  }

  std::cout << response.data() << std::endl; // Raw response
  ```

- Issuing new **Tokens**:

  ```cpp
  std::map<std::string, std::string> tokenMeta = {
      {"name", "CrazyCoin"},      // Public name for the token
      {"fungibility", "fungible"}, // Fungibility style
      {"supply", "limited"},       // Supply style
      {"decimals", "2"}            // Decimal places
  };

  auto response = client->createToken(
      "CRZY",        // Token slug (ticker symbol)
      100000000,     // Initial amount to issue
      tokenMeta,
      {},            // units (optional, for stackable tokens)
      std::nullopt   // batchId (optional, for stackable tokens)
  );

  if (response.success()) {
      std::cout << "Token created successfully!" << std::endl;
  }

  std::cout << response.data() << std::endl; // Raw response
  ```

- Transferring **Tokens** to other users:

  ```cpp
  auto response = client->transferToken(
      "7bf38257401eb3b0f20cabf5e6cf3f14c76760386473b220d95fa1c38642b61d", // Recipient's bundle hash
      "CRZY",    // Token slug
      100,       // Amount
      {},        // units (optional, for stackable tokens)
      std::nullopt // batchId (optional, for stackable tokens)
  );

  if (response.success()) {
      std::cout << "Token transferred successfully!" << std::endl;
  }

  std::cout << response.data() << std::endl; // Raw response
  ```

- Creating a new **Rule**:

  ```cpp
  std::vector<RuleDefinition> rule = {
      // Rule definition
  };

  auto response = client->createRule(
      "MyMetaType",  // metaType
      "MyMetaId",    // metaId
      rule,
      std::nullopt   // policy (optional)
  );

  if (response.success()) {
      std::cout << "Rule created successfully!" << std::endl;
  }

  std::cout << response.data() << std::endl; // Raw response
  ```

- Querying **Atoms**:

  ```cpp
  auto response = client->queryAtom(
      std::make_optional("molecular_hash_here"),
      std::make_optional("bundle_hash_here"),
      std::make_optional(Isotope::V),
      std::make_optional("CRZY"),
      true,  // latest
      15,    // limit
      1      // offset
  );

  std::cout << response.data() << std::endl; // Raw response
  ```

- Working with **Buffer Tokens**:

  ```cpp
  // Deposit to buffer
  std::map<std::string, double> tradeRates = {{"OTHER_TOKEN", 0.5}};

  auto depositResponse = client->depositBufferToken(
      "CRZY",          // tokenSlug
      100,             // amount
      tradeRates       // tradeRates
  );

  // Withdraw from buffer
  auto withdrawResponse = client->withdrawBufferToken(
      "CRZY",  // tokenSlug
      50       // amount
  );

  std::cout << depositResponse.data() << " " << withdrawResponse.data() << std::endl;
  ```

- Getting client information:

  ```cpp
  // Get bundle hash
  std::string bundleHash = client->getBundle();
  std::cout << "Bundle: " << bundleHash << std::endl;

  // Check if authenticated
  bool authenticated = client->isAuthenticated();
  ```

## Advanced Usage: Working with Molecules

For more granular control, you can work directly with Molecules:

- Create a new Molecule:
  ```cpp
  #include <knishio/Molecule.h>

  knishio::Molecule molecule(
      secret,
      sourceWallet,
      cellSlug
  );
  ```

- Create a custom Mutation:
  ```cpp
  #include <knishio/mutation/MutationProposeMolecule.h>

  knishio::mutation::MutationProposeMolecule mutation(molecule);
  ```

- Sign and check a Molecule:
  ```cpp
  molecule.sign();

  if (molecule.check()) {
      std::cout << "Molecule validation passed!" << std::endl;
  } else {
      std::cout << "Molecule validation failed!" << std::endl;
  }
  ```

- Execute a custom Query or Mutation:
  ```cpp
  auto response = client->executeQuery(mutation);

  if (response.success()) {
      std::cout << "Molecule executed successfully!" << std::endl;
  }
  ```

## The Hard Way: DIY Everything

This method involves individually building Atoms and Molecules, triggering the signature and validation processes, and communicating the resulting signed Molecule mutation or Query to a Knish.IO node via GraphQL.

1. Include the relevant classes in your application code:
    ```cpp
    #include <knishio/Molecule.h>
    #include <knishio/Wallet.h>
    #include <knishio/Atom.h>
    #include <knishio/crypto/Crypto.h>
    ```

2. Generate a 2048-symbol hexadecimal secret, either randomly, or via hashing login + password + salt, OAuth secret ID, biometric ID, or any other static value.

3. (optional) Initialize a signing wallet with:
   ```cpp
   knishio::Wallet wallet(
       secret,           // secret
       token,            // token
       position,         // position (optional)
       characters        // characters (optional)
   );
   ```

   **WARNING 1:** If ContinuID is enabled on the node, you will need to use a specific wallet, and therefore will first need to query the node to retrieve the `position` for that wallet.

   **WARNING 2:** The Knish.IO protocol mandates that all C and M transactions be signed with a `USER` token wallet.

4. Build your molecule with:
   ```cpp
   knishio::Molecule molecule(
       secret,              // secret
       sourceWallet,        // sourceWallet (optional)
       remainderWallet,     // remainderWallet (optional)
       cellSlug             // cellSlug (optional)
   );
   ```

5. Either use one of the shortcut methods provided by the `Molecule` class (which will build `Atom` instances for you), or create `Atom` instances yourself.

   DIY example:
    ```cpp
    // This example records a new Wallet on the ledger

    // Define metadata for our new wallet
    std::map<std::string, std::string> newWalletMeta = {
        {"address", newWallet.address},
        {"token", newWallet.token},
        {"bundle", newWallet.bundle},
        {"position", newWallet.position},
        {"batchId", newWallet.batchId}
    };

    // Build the C isotope atom
    knishio::Atom walletCreationAtom(
        sourceWallet.position,    // position
        sourceWallet.address,     // walletAddress
        Isotope::C,               // isotope
        sourceWallet.token        // token
    );
    walletCreationAtom.metaType = "wallet";
    walletCreationAtom.metaId = newWallet.address;
    walletCreationAtom.meta = newWalletMeta;
    walletCreationAtom.index = molecule.generateIndex();

    // Add the atom to our molecule
    molecule.addAtom(walletCreationAtom);

    // Adding a ContinuID / remainder atom
    molecule.addContinuIdAtom();
    ```

   Molecule shortcut method example:
    ```cpp
    // This example commits metadata to some Meta Asset

    // Defining our metadata
    std::map<std::string, std::string> metadata = {
        {"foo", "Foo"},
        {"bar", "Bar"}
    };

    molecule.initMeta(
        metadata,
        "MyMetaType",
        "MetaId123"
    );
    ```

6. Sign the molecule with the stored user secret:
    ```cpp
    molecule.sign();
    ```

7. Make sure everything checks out by verifying the molecule:
    ```cpp
    if (knishio::Molecule::verify(molecule)) {
        std::cout << "Molecule validation passed!" << std::endl;
    } else {
        std::cout << "Molecule validation failed!" << std::endl;
    }
    ```

8. Broadcast the molecule to a Knish.IO node:
    ```cpp
    #include <knishio/mutation/MutationProposeMolecule.h>

    // Build our mutation object
    knishio::mutation::MutationProposeMolecule mutation(molecule);

    // Send the mutation to the node and get a response
    auto response = client->executeQuery(mutation);
    ```

9. Inspect the response...
    ```cpp
    // For basic queries, we look at the data property:
    std::cout << response.data() << std::endl;

    // For mutations, check if the molecule was accepted by the ledger:
    std::cout << (response.success() ? "Success" : "Failed") << std::endl;

    // We can also check the reason for rejection
    std::cout << response.reason() << std::endl;

    // Some queries may also produce a payload, with additional data:
    std::cout << response.payload() << std::endl;
    ```

   Payloads are provided by responses to the following queries:
    1. `QueryBalance` and `QueryContinuId` -> returns a `Wallet` instance
    2. `QueryWalletList` -> returns a list of `Wallet` instances
    3. `MutationProposeMolecule`, `MutationRequestAuthorization`, `MutationCreateIdentifier`, `MutationLinkIdentifier`, `MutationClaimShadowWallet`, `MutationCreateToken`, `MutationRequestTokens`, and `MutationTransferTokens` -> returns molecule metadata

## Getting Help

Knish.IO is under active development, and our team is ready to assist with integration questions. The best way to seek help is to stop by our [Telegram Support Channel](https://t.me/wishknish). You can also [send us a contact request](https://knish.io/contact) via our website.
