/**
 * @file wots_signature_parity.cpp
 * @brief The C++ WOTS+ one-time signature must be byte-compatible with the other seven SDKs:
 *        it must PRODUCE what they produce, and ACCEPT what they accept.
 *
 * Both halves matter and only together. Before this test the C++ SDK emitted an uncompressed
 * 2048-hex OTS while JS, TS, Python, PHP, Kotlin, Rust and C all emitted the 1368-char base64
 * form, and Molecule::verify() never called verifyOts() — so nothing in the C++ tree noticed
 * that six peers rejected every molecule it signed. A sign-side-only test would not have caught
 * the missing verify leg, and a verify-side-only test would not have caught the format.
 *
 * Vectors: the shared cross-SDK master (vendored at tests/fixtures/).
 *   - `wotsSignedMetadataMolecule` is the self-test metaCreation molecule signed by
 *     KnishIO-Client-JS, whose otsFragments six other SDKs reproduced byte-identically.
 *   - `legacyMlkem768AuthMolecule` is a second, structurally different (U+I) signed molecule.
 *
 * The acceptance rule under test is the reference's, not a stricter local one: a 2048-char hex
 * OTS is taken as-is, anything else must base64-decode to exactly 2048 hex. C++ must not reject
 * a molecule the JS reference, the C SDK or the Rust validator would accept.
 */
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
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

std::string joinFragments(const Molecule& molecule) {
    std::string joined;
    for (const auto& atom : molecule.atoms) {
        joined += atom.otsFragment;
    }
    return joined;
}

std::string fragmentLengths(const Molecule& molecule) {
    std::string out = "[";
    for (size_t i = 0; i < molecule.atoms.size(); ++i) {
        if (i > 0) out += ",";
        out += std::to_string(molecule.atoms[i].otsFragment.size());
    }
    return out + "]";
}

// The self-tests' fixed remainder wallet (self-test-compatible.cpp:77-84) — the same position
// every SDK uses, so the molecule below is the one frozen in the vector.
Wallet createFixedRemainderWallet(const std::string& secret, const std::string& token) {
    return Wallet(secret, token,
                  "bbbb000000000000cccc111111111111dddd222222222222eeee333333333333");
}

// setFixedTimestamps (self-test-compatible.cpp:67-72): base + 1000*index.
void setFixedTimestamps(Molecule& molecule) {
    constexpr uint64_t base = 1700000000000ULL;
    for (size_t i = 0; i < molecule.atoms.size(); ++i) {
        molecule.atoms[i].createdAt = std::chrono::milliseconds(base + (i * 1000));
    }
}

}  // namespace

int main() {
    json vectors;
    try {
        vectors = loadVectors();
    } catch (const std::exception& e) {
        std::cerr << "wots_signature_parity: " << e.what() << std::endl;
        return 2;
    }

    const auto& root = vectors.at("vectors");
    const auto& frozen = root.at("wotsSignedMetadataMolecule");
    const json frozenMolecule = frozen.at("molecule");

    std::cout << "\nC++ accepts the signatures the other SDKs produce" << std::endl;

    // (1) The reference's own base64 OTS, on a real JS-signed molecule. This is the decode path
    //     that did not exist before: 1368 base64 chars -> 2048 hex -> 16 chunks of 128.
    try {
        const Molecule molecule = Molecule::jsonToObject(frozenMolecule.dump());
        check(Molecule::verifyOts(molecule),
              "verifyOts() accepts the frozen JS-signed base64 OTS (684/684)",
              "fragment lengths " + fragmentLengths(molecule));
        check(Molecule::verify(molecule),
              "verify() accepts it end to end (hash + isotope + OTS)",
              "verifyMolecularHash=" + std::string(Molecule::verifyMolecularHash(molecule) ? "true" : "false") +
                  " verifyOts=" + std::string(Molecule::verifyOts(molecule) ? "true" : "false"));
    } catch (const std::exception& e) {
        check(false, "verifyOts() accepts the frozen JS-signed base64 OTS (684/684)",
              std::string("threw: ") + e.what());
    }

    // (2) A structurally different signed molecule (U + I atoms, ML-KEM pubkey meta) from the
    //     same master. One passing molecule could be a coincidence of that molecule's shape.
    try {
        const Molecule molecule =
            Molecule::jsonToObject(root.at("legacyMlkem768AuthMolecule").at("molecule").dump());
        check(Molecule::verify(molecule),
              "verify() accepts the frozen U+I auth molecule's base64 OTS",
              "fragment lengths " + fragmentLengths(molecule));
    } catch (const std::exception& e) {
        check(false, "verify() accepts the frozen U+I auth molecule's base64 OTS",
              std::string("threw: ") + e.what());
    }

    // (3) One flipped base64 character in a fragment must be rejected. Without this, "accepts
    //     everything" would pass checks (1) and (2) just as well. The second assertion is the
    //     one that pins the WIRING: a molecular hash still matching its atoms and a conserved
    //     isotope-V sum say nothing about the signature, so a verify() that does not call
    //     verifyOts() accepts this forgery — which is exactly what C++ used to do.
    try {
        json tampered = frozenMolecule;
        std::string fragment = tampered.at("atoms").at(1).at("otsFragment").get<std::string>();
        fragment[10] = (fragment[10] == 'A') ? 'B' : 'A';
        tampered["atoms"][1]["otsFragment"] = fragment;

        const Molecule molecule = Molecule::jsonToObject(tampered.dump());
        check(!Molecule::verifyOts(molecule),
              "verifyOts() rejects a single flipped OTS character",
              "accepted a tampered signature");
        check(!Molecule::verify(molecule),
              "verify() rejects it too, so the OTS leg is actually wired in",
              "verify() accepted a forged signature; verifyMolecularHash=" +
                  std::string(Molecule::verifyMolecularHash(molecule) ? "true" : "false"));
    } catch (const std::exception& e) {
        check(false, "verifyOts() rejects a single flipped OTS character",
              std::string("threw: ") + e.what());
    }

    // (4) Malformed length. Dropping one whole base64 group (4 chars) drops 3 signature bytes,
    //     so the OTS decodes to 2046 hex and the reference raises SignatureMalformedException.
    //     Note one or two trailing characters would NOT do: `Xy==` and `Xy` decode to the same
    //     byte, in the reference decoder as well as ours, so such a truncation is not malformed.
    try {
        json truncated = frozenMolecule;
        std::string fragment = truncated.at("atoms").at(1).at("otsFragment").get<std::string>();
        fragment.resize(fragment.size() - 4);
        truncated["atoms"][1]["otsFragment"] = fragment;

        const Molecule molecule = Molecule::jsonToObject(truncated.dump());
        const std::string decoded = base64ToHex(joinFragments(molecule));
        check(decoded.size() != 2048 && !Molecule::verifyOts(molecule),
              "verifyOts() rejects an OTS that does not decode to 2048 hex",
              "decoded to " + std::to_string(decoded.size()) + " hex chars");
    } catch (const std::exception& e) {
        check(false, "verifyOts() rejects an OTS that does not decode to 2048 hex",
              std::string("threw: ") + e.what());
    }

    // (5) Uncompressed 2048-hex is still valid, exactly as in JS CheckMolecule.ots(), the C SDK
    //     and the Rust validator. Pins the rule so a later "base64 only" tightening cannot land
    //     here alone and start rejecting molecules the on-ledger validator accepts.
    try {
        json uncompressed = frozenMolecule;
        const std::string hex = base64ToHex(
            frozen.at("expectedOtsFragments").at(0).get<std::string>() +
            frozen.at("expectedOtsFragments").at(1).get<std::string>());
        uncompressed["atoms"][0]["otsFragment"] = hex.substr(0, 1024);
        uncompressed["atoms"][1]["otsFragment"] = hex.substr(1024);

        const Molecule molecule = Molecule::jsonToObject(uncompressed.dump());
        check(hex.size() == 2048 && Molecule::verifyOts(molecule),
              "verifyOts() still accepts the uncompressed 2048-hex form (1024/1024)",
              "hex length " + std::to_string(hex.size()));
    } catch (const std::exception& e) {
        check(false, "verifyOts() still accepts the uncompressed 2048-hex form (1024/1024)",
              std::string("threw: ") + e.what());
    }

    std::cout << "\nC++ produces the signatures the other SDKs accept" << std::endl;

    // (6) Sign shape on the vector's own inputs: 2 atoms -> 684/684 base64, self-verifying.
    //     Byte identity against the vector is asserted by the self-test, which builds this same
    //     molecule; this pins the SHAPE so the two can never disagree about what was measured.
    try {
        const std::string secret =
            knishio::KnishIOClient::generateSecret(frozen.at("seed").get<std::string>());
        const std::string token = frozen.at("token").get<std::string>();
        Wallet source(secret, token, frozen.at("sourcePosition").get<std::string>());
        Wallet remainder = createFixedRemainderWallet(secret, token);

        Molecule molecule;
        molecule.sourceWallet = std::make_shared<Wallet>(source);
        molecule.remainderWallet = std::make_shared<Wallet>(remainder);
        molecule.initMeta(source,
                          {{"name", "Test Metadata"},
                           {"description", "This is a test metadata for SDK testing."}},
                          frozen.at("metaType").get<std::string>(),
                          frozen.at("metaId").get<std::string>());
        setFixedTimestamps(molecule);
        molecule.sign(secret);

        const std::string joined = joinFragments(molecule);
        check(molecule.atoms.size() == 2 && joined.size() == 1368 &&
                  molecule.atoms[0].otsFragment.size() == 684 &&
                  molecule.atoms[1].otsFragment.size() == 684,
              "sign() emits a 1368-char base64 OTS chunked 684/684 across 2 atoms",
              std::to_string(molecule.atoms.size()) + " atoms, lengths " + fragmentLengths(molecule) +
                  ", total " + std::to_string(joined.size()));
        check(joined.size() >= 2 && joined.compare(joined.size() - 2, 2, "==") == 0,
              "the signature is base64 of 1024 bytes (1024 % 3 == 1, so it ends in '==')",
              "ends in '" + joined.substr(joined.size() >= 2 ? joined.size() - 2 : 0) + "'");
        check(Molecule::verify(molecule),
              "the molecule it just signed verifies, OTS leg included",
              "verifyOts=" + std::string(Molecule::verifyOts(molecule) ? "true" : "false"));
    } catch (const std::exception& e) {
        check(false, "sign() emits a 1368-char base64 OTS chunked 684/684 across 2 atoms",
              std::string("threw: ") + e.what());
    }

    // (7) Chunk count must equal atom count for an atom count that does not divide 1368.
    //     ceil(1368/7) = 196 -> 7 chunks (196*6 + 192). std::round(1368/7.0) = 195 -> 8 chunks,
    //     and the assignment loop then writes atoms[7] on a 7-atom molecule: an out-of-bounds
    //     write, not merely a parity break. 7 atoms = V source + 5 V recipients + V remainder.
    try {
        const std::string secret = knishio::KnishIOClient::generateSecret("wots-ceil-chunking-seed");
        const std::string token = "USER";
        Wallet source(secret, token);
        source.balance = "1000";

        std::vector<Wallet> recipients;
        std::vector<std::string> amounts;
        for (int i = 0; i < 5; ++i) {
            recipients.emplace_back(
                knishio::KnishIOClient::generateSecret("wots-ceil-recipient-" + std::to_string(i)), token);
            amounts.emplace_back("100");
        }
        Wallet remainder(secret, token);

        Molecule molecule;
        molecule.initValues(source, recipients, amounts, remainder);
        setFixedTimestamps(molecule);
        molecule.sign(secret);

        check(molecule.atoms.size() == 7, "initValues with 5 recipients builds 7 atoms",
              std::to_string(molecule.atoms.size()) + " atoms");

        bool allChunked = molecule.atoms.size() == 7;
        for (const auto& atom : molecule.atoms) {
            allChunked = allChunked && !atom.otsFragment.empty();
        }
        check(allChunked, "every one of the 7 atoms receives an OTS chunk (chunks == atoms)",
              "lengths " + fragmentLengths(molecule));
        check(fragmentLengths(molecule) == "[196,196,196,196,196,196,192]",
              "ceil chunking gives [196 x6, 192], not round()'s 8 chunks of 195",
              "lengths " + fragmentLengths(molecule) + ", total " +
                  std::to_string(joinFragments(molecule).size()));
        check(Molecule::verify(molecule), "the 7-atom molecule verifies, OTS leg included",
              "verifyOts=" + std::string(Molecule::verifyOts(molecule) ? "true" : "false"));
    } catch (const std::exception& e) {
        check(false, "ceil chunking gives [196 x6, 192], not round()'s 8 chunks of 195",
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
