# Knish.IO C++ Client
This is an experimental C++ implementation of the Knish.IO API client. Its purpose is to expose class libraries for building and signing Knish.IO Molecules, composing Atoms (presently "M" and "V" isotopes are supported), and generating Wallet addresses (public keys) and private keys as per the Knish.IO Technical Whitepaper.

# Getting Started
1. Download Libsodium 1.0.18 from here: https://github.com/jedisct1/libsodium/releases/tag/1.0.18-RELEASE. Check https://download.libsodium.org/doc/installation for installation notes. Note: there are prebuilt binaries for Visual Studio 2010-2019.
2. Create a new Visual C++ project or open a existing one.
3. Add all Knish.IO C++ Client header and source files to the project.
4. Add Libsodium as dependency to the project.
5. Build a 2048-character user secret via your preferred methodology (random string?).
6. Initialize a wallet with `Wallet wallet = new Wallet(secret, token);`.

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