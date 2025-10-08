# KnishIO C++ SDK

A modern C++20 implementation of the Knish.IO SDK for post-blockchain distributed ledger technology. This SDK provides comprehensive support for building and signing Molecules, composing Atoms, managing Wallets, and interacting with Knish.IO nodes via GraphQL.

## Features

- **Modern C++20** - Leverages latest language features for safety and performance
- **Builder Pattern** - Flexible client configuration  
- **Async Operations** - Non-blocking API calls using std::future
- **GraphQL Support** - Full query and mutation support
- **Security First** - Quantum-resistant cryptography, secure memory handling
- **Cross-Platform** - Works on Linux, macOS, and Windows

## Requirements

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 2019+)
- CMake 3.20 or higher
- libsodium 1.0.18+
- libcurl 7.0+
- POSIX threads

## Building with CMake

```bash
# Clone and build
mkdir build && cd build
cmake ..
cmake --build . --parallel 4

# Run tests
ctest

# Build examples
cmake -DKNISHIO_BUILD_EXAMPLES=ON ..
cmake --build .
```

## Quick Start

### Initialize Client

```cpp
#include <knishio/KnishIOClient.h>

auto client = knishio::KnishIOClient::Builder()
    .uris({"https://node1.knish.io", "https://node2.knish.io"})
    .cellSlug("my-cell")
    .enableLogging(true)
    .build();

// Generate secret and initialize wallet
std::string secret = knishio::KnishIOClient::generateSecret(2048);
client->setSecret(secret);
```

### Query Operations

```cpp
#include <knishio/query/QueryBalance.h>
#include <knishio/http/GraphQLClient.h>

knishio::http::GraphQLClient graphql("https://node.knish.io", 10000, 3);
knishio::query::QueryBalance query(&graphql);

auto response = query.execute(
    std::nullopt,    // address
    bundleHash,      // bundleHash
    "USER",         // token
    std::nullopt,    // position  
    std::nullopt     // type
);
```

## Traditional Usage

### Initialize Wallet

```cpp
Wallet wallet(secret, token);
```

You can also specify a third, optional `position` argument represents the private key index (hexadecimal), and must NEVER be used more than once. It will be generated randmly if not provided.

A fourth argument, `saltLength`, helps tweak the length of the random `position`, if the parameter is not provided.

The `token` argument (string) is the slug for the token being transacted with. Knish.IO anticipates user's personal metadata being kept under the `USER` token.

# Building Your Molecule
1. Build your molecule with `Molecule molecule(cellId);` The `cellId` argument represents the slug for your Knish.IO cell. It's meant to segregate molecules of one use case from others. Leave it as empty string if not sure.
2. For a "M"-type molecule, build your metadata as a standard map, for example:
```cpp
std::map<std::string, std::string> data =
{
    { "name", "foo" },
    { "email", "bar" }
    //...
};
```
3. Initialize the molecule as "M"-type: `molecule.initMeta(wallet, data, metaType, metaId);` The `metaType` and `metaId` arguments represent a polymorphic key to whatever asset you are attaching this metadata to.
4. Sign the molecule with the user secret: `molecule.sign(secret);`
5. Make sure everything checks out by verifying the molecule:
```cpp
if (Molecule::verify(molecule))
{
    //...  Do stuff? Send the molecule to a Knish.IO node, maybe?
}
```

# Broadcasting
1. Knish.IO nodes use GraphQL to receive new molecules as a Mutation. The code for the mutation is as follows:
```
  mutation MoleculeMutation($molecule: MoleculeInput!) {
    ProposeMolecule(
      molecule: $molecule,
    ) {
      molecularHash,
      height,
      depth,
      status,
      reason,
      reasonPayload,
      createdAt,
      receivedAt,
      processedAt,
      broadcastedAt
    }
  }
```
2. Use your favorite GraphQL client to send the mutation to a Knish.IO node with the molecule you've signed as the only parameter.
3. The `status` field of the response will indicate whether the molecule was accepted or rejected, or if it's pending further processing. The `reason` and `reasonPayload` fields can help further diagnose and handle rejections.