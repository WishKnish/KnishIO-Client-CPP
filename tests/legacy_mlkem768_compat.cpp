/**
 * @file legacy_mlkem768_compat.cpp
 * @brief A build whose default parameter set is ML-KEM-1024 must still READ pre-bump
 *        ML-KEM-768 records, and must still validate a pre-bump signed 768 auth molecule.
 *
 * Every assertion below runs from a wallet constructed at the DEFAULT parameter set (1024) —
 * no explicit step-back, no second wallet handed to the caller. The 64-byte d‖z ML-KEM seed is
 * parameter-set-independent, so a wallet derives its own 768 identity on demand from key
 * material it already holds; that is what makes "a 1024 client reads 768 records" literally
 * true rather than true-if-the-caller-knows-to-build-a-second-wallet.
 *
 * The asymmetry under test is deliberate: inbound is PERMISSIVE, outbound stays STRICT.
 * Decapsulating a 768 ciphertext addressed to our own 768 identity downgrades nothing — that
 * message's confidentiality was fixed at 768 by its sender. Encapsulation is where downgrade
 * risk lives, so the length guard there must remain, and the advertised public key must stay
 * single-set (it goes into signed molecule meta and into auth).
 *
 * Vectors: the shared cross-SDK master (vendored at tests/fixtures/). `mlkem768.decrypt` is a
 * genuine pre-bump artifact, unchanged across the migration; `legacyMlkem768AuthMolecule` is a
 * signed U+I auth molecule whose U-atom walletPubkey meta is a 1184-byte ML-KEM-768 key.
 */
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "Atom.h"
#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "utility.h"
#include "third_party/nlohmann/json.hpp"

using json = nlohmann::json;
using KnishIO::Atom;
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

json loadVectors() {
    std::vector<std::string> candidates;
    if (const char* env = std::getenv("KNISHIO_CROSS_PLATFORM_VECTORS")) {
        candidates.emplace_back(env);
    }
#ifdef KNISHIO_VECTORS_PATH
    candidates.emplace_back(KNISHIO_VECTORS_PATH);
#endif
    candidates.emplace_back("tests/fixtures/cross-platform-test-vectors.json");
    if (const char* sd = std::getenv("KNISHIO_SHARED_RESULTS")) {
        candidates.emplace_back(std::string(sd) + "/cross-platform-test-vectors.json");
    }

    std::ifstream f;
    for (const auto& p : candidates) {
        f.open(p);
        if (f.is_open()) {
            break;
        }
        f.clear();
    }
    if (!f.is_open()) {
        // A missing fixture is a hard failure here: the whole point of this binary is the
        // fixture, so skipping would publish a pass having asserted nothing.
        throw std::runtime_error("cross-platform-test-vectors.json not found");
    }
    return json::parse(f);
}

}  // namespace

int main() {
    json vectors;
    try {
        vectors = loadVectors();
    } catch (const std::exception& e) {
        std::cerr << "legacy_mlkem768_compat: " << e.what() << std::endl;
        return 2;
    }

    const auto& root = vectors.at("vectors");
    const auto& dec768 = root.at("mlkem768").at("decrypt");

    const auto secret = dec768.at("secret").get<std::string>();
    const auto token = dec768.at("token").get<std::string>();
    const auto position = dec768.at("position").get<std::string>();
    const auto expectedPlaintext = dec768.at("expectedPlaintext").get<std::string>();
    const std::map<std::string, std::string> envelope768 = {
        {"cipherText", dec768.at("cipherText").get<std::string>()},
        {"encryptedMessage", dec768.at("encryptedMessage").get<std::string>()}
    };

    std::cout << "A 1024-default build reads pre-bump ML-KEM-768 records" << std::endl;

    // (a) Dual-identity inbound decryption: the default (1024) wallet decapsulates a 1088-byte
    //     768 ciphertext by deriving its own 768 identity on demand.
    try {
        Wallet wallet(secret, token, position);
        check(wallet.mlkem_parameter_set == 1024, "the wallet under test really is at the 1024 default",
              "mlkem_parameter_set = " + std::to_string(wallet.mlkem_parameter_set));
        const std::string plaintext = wallet.decryptMessageML(envelope768);
        check(plaintext == expectedPlaintext,
              "a default (1024) wallet decrypts a frozen 768 envelope addressed to its own 768 identity",
              "got: " + plaintext);

        // The derived identity must be released, not cached: after reading a 768 record the
        // wallet is still an ML-KEM-1024 wallet holding only its 1024 keypair.
        check(wallet.mlkem_parameter_set == 1024 &&
                  wallet.mlkem_private_key.size() == 3168 &&
                  wallet.mlkem_public_key.size() == 1568,
              "the derived 768 identity is not cached on the wallet",
              "parameter set " + std::to_string(wallet.mlkem_parameter_set) + ", privkey " +
                  std::to_string(wallet.mlkem_private_key.size()) + " bytes, pubkey " +
                  std::to_string(wallet.mlkem_public_key.size()) + " bytes");
    } catch (const std::exception& e) {
        check(false, "a default (1024) wallet decrypts a frozen 768 envelope addressed to its own 768 identity",
              std::string("threw: ") + e.what());
    }

    // (b) Permissive inbound must NOT move what the wallet advertises — that value lands in
    //     signed molecule meta and in auth, so moving it would change hashed bytes.
    try {
        Wallet wallet(secret, token, position);
        const size_t rawBytes = wallet.mlkem_public_key.size();
        const size_t decodedBytes = fromBase64(toBase64(wallet.mlkem_public_key)).size();
        check(rawBytes == 1568 && decodedBytes == 1568,
              "the advertised public key is still ML-KEM-1024 (1568 bytes)",
              "raw " + std::to_string(rawBytes) + " / decoded " + std::to_string(decodedBytes));
    } catch (const std::exception& e) {
        check(false, "the advertised public key is still ML-KEM-1024 (1568 bytes)",
              std::string("threw: ") + e.what());
    }

    // (c) Outbound stays STRICT. C++ had no encapsulation-guard test to confirm, so this is it:
    //     a careless permissive-inbound change that also relaxed encapsulation would pass every
    //     other assertion in this file.
    try {
        Wallet wallet(secret, token, position);
        Wallet wallet768(secret, token, position, 64, 768);
        bool threw = false;
        std::string message;
        try {
            wallet.encryptMessageML("downgrade probe", toBase64(wallet768.mlkem_public_key));
        } catch (const std::invalid_argument& e) {
            threw = true;
            message = e.what();
        }
        check(threw && message.find("expected 1568 (ML-KEM-1024)") != std::string::npos,
              "encapsulating to a 1184-byte key still throws — outbound is not permissive",
              threw ? ("message: " + message) : "no exception thrown");
    } catch (const std::exception& e) {
        check(false, "encapsulating to a 1184-byte key still throws — outbound is not permissive",
              std::string("threw while setting up: ") + e.what());
    }

    // (d) A ciphertext at NEITHER parameter set must still fail on this SDK's own observable.
    //     C++ throws where JS/TS/Python/PHP/Kotlin return a null-ish value; assert what it
    //     actually does rather than harmonising it.
    try {
        Wallet wallet(secret, token, position);
        std::map<std::string, std::string> malformed = envelope768;
        malformed["cipherText"] = toBase64(std::vector<uint8_t>(64, 0));
        bool threw = false;
        std::string message;
        try {
            wallet.decryptMessageML(malformed);
        } catch (const std::invalid_argument& e) {
            threw = true;
            message = e.what();
        }
        check(threw && message == "Invalid ML-KEM ciphertext size",
              "a ciphertext matching neither parameter set still throws std::invalid_argument",
              threw ? ("message: " + message) : "no exception thrown");
    } catch (const std::exception& e) {
        check(false, "a ciphertext matching neither parameter set still throws std::invalid_argument",
              std::string("threw while setting up: ") + e.what());
    }

    // (e) The transport path is map-addressed: a pre-bump sender addressed the envelope to
    //     hashShare(our_768_pubkey), so without trying both hash shares the length dispatch in
    //     (a) is never even reached.
    try {
        Wallet wallet(secret, token, position);
        Wallet wallet768(secret, token, position, 64, 768);
        json map;
        map[wallet768.hashShare(toBase64(wallet768.mlkem_public_key))] = envelope768;

        // decryptMyMessageML returns the RAW decrypted text (the transport parses it) — the
        // frozen payload is a JSON-encoded string, so decode before comparing.
        const std::string raw = wallet.decryptMyMessageML(map.dump());
        std::string decoded;
        if (!raw.empty()) {
            try {
                decoded = json::parse(raw).get<std::string>();
            } catch (const std::exception&) {
                decoded = raw;
            }
        }
        check(!raw.empty() && decoded == expectedPlaintext,
              "the CipherHash map path finds an envelope addressed to the 768 hash share",
              raw.empty() ? "returned an empty string (no matching hash share)" : ("got: " + decoded));
    } catch (const std::exception& e) {
        check(false, "the CipherHash map path finds an envelope addressed to the 768 hash share",
              std::string("threw: ") + e.what());
    }

    std::cout << "\nA pre-bump ML-KEM-768 auth molecule validates from a 1024 default" << std::endl;

    const auto& legacy = root.at("legacyMlkem768AuthMolecule");

    // The record really is a 768 record. Fails loudly if the fixture is ever regenerated at the
    // 1024 default, at which point it would no longer be evidence about pre-bump records.
    try {
        std::vector<std::string> walletPubkeys;
        for (const auto& atom : legacy.at("molecule").at("atoms")) {
            if (!atom.contains("meta") || atom.at("meta").is_null()) {
                continue;
            }
            for (const auto& meta : atom.at("meta")) {
                if (meta.at("key").get<std::string>() == "walletPubkey") {
                    walletPubkeys.push_back(meta.at("value").get<std::string>());
                }
            }
        }
        const auto expectedBytes = legacy.at("expectedWalletPubkeyBytes").get<size_t>();
        const size_t actualBytes = walletPubkeys.size() == 1 ? fromBase64(walletPubkeys.front()).size() : 0;
        check(walletPubkeys.size() == 1 && actualBytes == expectedBytes,
              "the U-atom walletPubkey meta really is an ML-KEM-768 key",
              std::to_string(walletPubkeys.size()) + " key(s), " + std::to_string(actualBytes) +
                  " bytes, expected " + std::to_string(expectedBytes));
    } catch (const std::exception& e) {
        check(false, "the U-atom walletPubkey meta really is an ML-KEM-768 key",
              std::string("threw: ") + e.what());
    }

    // Molecular hash over the frozen hashable atom array, via the same function the existing
    // molecular_hash vectors use.
    try {
        std::vector<Atom> atoms;
        for (const auto& atom : legacy.at("atoms")) {
            atoms.push_back(Atom::jsonToObject(atom.dump()));
        }
        const std::string hash = Atom::hashAtomsBase17(atoms);
        const auto expected = legacy.at("expectedMolecularHash").get<std::string>();
        check(hash == expected, "its molecular hash still verifies", "got " + hash + ", expected " + expected);
    } catch (const std::exception& e) {
        check(false, "its molecular hash still verifies", std::string("threw: ") + e.what());
    }

    // Molecule::verify() = verifyMolecularHash + verifyTokenIsotopeV + verifyOts. The OTS leg
    // needs no sender wallet — it rebuilds the signing address out of the fragments — so this
    // also verifies the frozen molecule's JS-produced 684/684 base64 WOTS+ signature.
    try {
        const Molecule molecule = Molecule::jsonToObject(legacy.at("molecule").dump());
        const auto expected = legacy.at("expectedMolecularHash").get<std::string>();
        check(molecule.molecularHash == expected, "the deserialized molecule carries the frozen hash",
              "got " + molecule.molecularHash);
        check(Molecule::verify(molecule), "Molecule::verify() passes (hash + isotope-V conservation + OTS)",
              "verifyMolecularHash=" + std::string(Molecule::verifyMolecularHash(molecule) ? "true" : "false") +
                  " verifyTokenIsotopeV=" + std::string(Molecule::verifyTokenIsotopeV(molecule) ? "true" : "false") +
                  " verifyOts=" + std::string(Molecule::verifyOts(molecule) ? "true" : "false"));
    } catch (const std::exception& e) {
        check(false, "Molecule::verify() passes (hash + isotope-V conservation + OTS)",
              std::string("threw: ") + e.what());
    }

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
