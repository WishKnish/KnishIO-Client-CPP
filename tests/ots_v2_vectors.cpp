/**
 * @file ots_v2_vectors.cpp
 * @brief OTS v2 (64-chain WOTS+): key derivation, address, normalized hash, ML-KEM identities
 *        of v2 wallets, molecule verdicts and malformed declared hashes.
 *
 * Two modes, registered as two CTest entries:
 *   - `roundtrip` (OtsV2RoundTrip): always runs. A v2 source wallet signs a molecule, the
 *     5464-char signature verifies, and one flipped character gives SignatureMismatchException.
 *   - `vectors` (OtsV2Vectors): the shared OTS v2 vectors, read from KNISHIO_OTS_V2_VECTORS or
 *     ../shared-test-results/ots-v2-vectors.json. A standalone checkout has no such file; the
 *     test then prints SKIP and exits 77, which CTest reports as skipped.
 */
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "Molecule.h"
#include "Wallet.h"
#include "utility.h"
#include "exception/KnishIOException.h"
#include "third_party/nlohmann/json.hpp"

using json = nlohmann::json;
using KnishIO::Molecule;
using KnishIO::Wallet;

namespace {

int failures = 0;

void check(bool ok, const std::string& name, const std::string& detail = {}) {
    std::cout << (ok ? "  \033[0;32mPASS\033[0m " : "  \033[0;31mFAIL\033[0m ") << name;
    if (!ok && !detail.empty()) {
        std::cout << "\n       " << detail;
    }
    std::cout << std::endl;
    if (!ok) {
        ++failures;
    }
}

// Names the outcome of a throwing verification call: "ok", "SignatureMalformed",
// "SignatureMismatch", or the text of any other exception.
template <typename F>
std::string outcome(F&& call) {
    try {
        call();
        return "ok";
    } catch (const knishio::SignatureMalformedException&) {
        return "SignatureMalformed";
    } catch (const knishio::SignatureMismatchException&) {
        return "SignatureMismatch";
    } catch (const std::exception& e) {
        return std::string("threw: ") + e.what();
    }
}

std::string joinFragments(const Molecule& molecule) {
    std::string joined;
    for (const auto& atom : molecule.atoms) {
        joined += atom.otsFragment;
    }
    return joined;
}

int runRoundTrip() {
    std::cout << "OTS v2 sign / verify round trip" << std::endl;

    std::string secret;
    for (int i = 0; i < 128; i++) {
        secret += "0123456789abcdef";
    }
    const std::string position(64, 'a');
    const std::vector<std::pair<std::string, std::string>> meta = {{"sample", "7"}};

    try {
        Wallet source(secret, "USER", position, 64, 1024, 2);
        Wallet remainder(secret, "USER", "", 64, 1024, source.ots_version);
        check(source.ots_version == 2 && source.key.size() == 8192, "a v2 wallet holds an 8192-hex key",
              "version " + std::to_string(source.ots_version) + ", key " + std::to_string(source.key.size()));
        check(remainder.ots_version == 2, "a remainder built at the source's version is v2");

        Molecule mol("");
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initMeta(source, meta, "OtsV2", "round-trip");
        check(mol.signingOtsVersion() == 2, "signingOtsVersion() follows the source wallet");
        mol.sign(secret);

        const std::string joined = joinFragments(mol);
        check(joined.size() == 5464, "the compressed v2 signature is 5464 characters",
              "got " + std::to_string(joined.size()));
        const std::string verdict = outcome([&] { Molecule::check(mol); });
        check(verdict == "ok", "Molecule::check() accepts the v2 molecule", verdict);
        check(Molecule::verify(mol), "Molecule::verify() accepts the v2 molecule");

        Molecule tampered = mol;
        std::string& fragment = tampered.atoms.front().otsFragment;
        const auto at = fragment.find_first_of("AB");
        check(at != std::string::npos, "atoms[0].otsFragment has an A or B to flip");
        if (at != std::string::npos) {
            fragment[at] = fragment[at] == 'A' ? 'B' : 'A';
            const std::string tamperedVerdict = outcome([&] { Molecule::check(tampered); });
            check(tamperedVerdict == "SignatureMismatch",
                  "one flipped character gives SignatureMismatchException", tamperedVerdict);
            check(!Molecule::verify(tampered), "Molecule::verify() returns false for it");
        }
    } catch (const std::exception& e) {
        check(false, "round trip", std::string("threw: ") + e.what());
    }

    try {
        Wallet unsupported("abcdef", "USER", "", 64, 1024, 3);
        check(false, "an unsupported OTS version is refused", "constructed a wallet");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 3; expected 1 or 2.",
              "an unsupported OTS version is refused", e.what());
    }

    return failures == 0 ? 0 : 1;
}

std::string vectorsPath() {
    if (const char* env = std::getenv("KNISHIO_OTS_V2_VECTORS")) {
        return env;
    }
#ifdef KNISHIO_OTS_V2_VECTORS_PATH
    return KNISHIO_OTS_V2_VECTORS_PATH;
#else
    return "../shared-test-results/ots-v2-vectors.json";
#endif
}

const json& findByName(const json& tests, const std::string& name) {
    for (const auto& t : tests) {
        if (t.at("name").get<std::string>() == name) {
            return t;
        }
    }
    throw std::runtime_error("vector not found: " + name);
}

int runVectors() {
    const std::string path = vectorsPath();
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "SKIP: ots-v2-vectors.json not found (standalone checkout)" << std::endl;
        return 77;
    }
    const json vectors = json::parse(file).at("vectors");
    const json& keyTests = vectors.at("key_derivation").at("tests");

    std::cout << "OTS v2 key derivation and address" << std::endl;
    for (const auto& v : keyTests) {
        const auto name = v.at("name").get<std::string>();
        try {
            const auto secret = v.at("secret").get<std::string>();
            const auto token = v.at("token").get<std::string>();
            const auto position = v.at("position").get<std::string>();
            const auto keyV1 = Wallet::generateWalletKey(secret, token, position);
            const auto keyV2 = Wallet::generateWalletKey(secret, token, position, 2);
            check(keyV1 == v.at("expectedKeyV1").get<std::string>(), name + ": v1 key");
            check(keyV2 == v.at("expectedKeyV2").get<std::string>(), name + ": v2 key");
            check(Wallet::generateWalletAddress(v.at("expectedKeyV1").get<std::string>()) ==
                      v.at("expectedAddressV1").get<std::string>(), name + ": v1 address");
            check(Wallet::generateWalletAddress(v.at("expectedKeyV2").get<std::string>()) ==
                      v.at("expectedAddressV2").get<std::string>(), name + ": v2 address");
            check(Wallet(secret, token, position, 64, 1024, 2).address == v.at("expectedAddressV2").get<std::string>(),
                  name + ": v2 wallet address");
        } catch (const std::exception& e) {
            check(false, name, std::string("threw: ") + e.what());
        }
    }
    try {
        (void)Wallet::generateWalletKey("abcdef", "USER", "abcdef", 3);
        check(false, "generateWalletKey refuses OTS version 3", "returned a key");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 3; expected 1 or 2.",
              "generateWalletKey refuses OTS version 3", e.what());
    }

    std::cout << "\nOTS v2 normalized hash" << std::endl;
    for (const auto& v : vectors.at("signature").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        const auto normalized = Molecule::normalize(Molecule::enumerate(v.at("molecularHash").get<std::string>()));
        std::vector<int> got(normalized.begin(), normalized.end());
        check(got == v.at("expectedNormalized").get<std::vector<int>>(), name + ": normalize(enumerate(hash))");
    }

    std::cout << "\nOTS v2 wallet ML-KEM identities" << std::endl;
    for (const auto& v : vectors.at("mlkem_identity").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        try {
            const json& k = findByName(keyTests, v.at("keyFrom").get<std::string>());
            const auto secret = k.at("secret").get<std::string>();
            const auto token = k.at("token").get<std::string>();
            const auto position = k.at("position").get<std::string>();
            check(toBase64(Wallet(secret, token, position, 64, 1024, 2).mlkem_public_key) ==
                      v.at("expectedMlKem1024Pubkey").get<std::string>(), name + ": ML-KEM-1024 public key");
            check(toBase64(Wallet(secret, token, position, 64, 768, 2).mlkem_public_key) ==
                      v.at("expectedMlKem768Pubkey").get<std::string>(), name + ": ML-KEM-768 public key");
        } catch (const std::exception& e) {
            check(false, name, std::string("threw: ") + e.what());
        }
    }

    std::cout << "\nOTS v2 molecule verdicts" << std::endl;
    const json& moleculeTests = vectors.at("molecules").at("tests");
    for (const auto& v : moleculeTests) {
        const auto name = v.at("name").get<std::string>();
        const auto expected = v.at("expected").get<std::string>();
        const std::string got = outcome([&] { Molecule::check(Molecule::jsonToObject(v.at("molecule").dump())); });
        check(got == (expected == "verified" ? "ok" : expected), name + " -> " + expected, "got " + got);
    }

    const json& user = findByName(keyTests, "hex_secret_user");
    for (const std::string name : {"genuine_v2", "genuine_v1_control"}) {
        try {
            const json& v = findByName(moleculeTests, name);
            const auto secret = user.at("secret").get<std::string>();
            Molecule molecule = Molecule::jsonToObject(v.at("molecule").dump());
            molecule.sourceWallet = std::make_shared<Wallet>(
                secret, "USER", user.at("position").get<std::string>(), 64, 1024, v.at("otsVersion").get<int>());
            molecule.sign(secret);
            const auto& atoms = v.at("molecule").at("atoms");
            bool same = atoms.size() == molecule.atoms.size();
            for (size_t i = 0; same && i < atoms.size(); i++) {
                same = molecule.atoms[i].otsFragment == atoms[i].at("otsFragment").get<std::string>();
            }
            check(same, "re-signing " + name + " reproduces every otsFragment");
        } catch (const std::exception& e) {
            check(false, "re-signing " + name, std::string("threw: ") + e.what());
        }
    }

    std::cout << "\nOTS malformed declared hash" << std::endl;
    for (const auto& v : vectors.at("malformed_hash").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        const auto expected = v.at("expected").get<std::string>();
        const std::string got = outcome([&] { Molecule::verifyOts(Molecule::jsonToObject(v.at("molecule").dump())); });
        check(got == expected, name + " -> " + expected, "got " + got);
    }

    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "roundtrip";
    int rc = 0;
    if (mode == "vectors") {
        rc = runVectors();
    } else {
        rc = runRoundTrip();
    }
    if (rc == 77) {
        return rc;
    }
    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
