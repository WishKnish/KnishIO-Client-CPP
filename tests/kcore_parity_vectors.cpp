/**
 * @file kcore_parity_vectors.cpp
 * @brief kcore parity vectors: full signed molecules (metadata, value transfer, token creation,
 *        wallet creation) at OTS v1 and v2, with unique and with colliding createdAt values.
 *
 * Reads the vendored copy of the shared master (tests/fixtures/kcore-parity-vectors.json;
 * KNISHIO_KCORE_PARITY_VECTORS overrides the path). For each of the 16 cases, under the backend
 * this build links (kcore with KNISHIO_USE_KCORE=ON, the SDK's own code otherwise):
 *   (a) verify: the molecule parses, its atoms hash to expected.molecularHash, and verifyOts()
 *       accepts the signature;
 *   (b) re-sign: the molecule's signatures are cleared and it is signed again from the case's
 *       secret and source wallet; molecularHash and every otsFragment must equal `expected` byte
 *       for byte.
 * The vectors pin kcore and the pure path to the same bytes, so the test is registered once and
 * runs in both builds (CI: `gate` and `gate-kcore`). A missing fixture is a failure, not a skip.
 */
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "Atom.h"
#include "Molecule.h"
#include "Wallet.h"
#include "exception/KnishIOException.h"
#include "third_party/nlohmann/json.hpp"

#ifdef KNISHIO_HAVE_KCORE
#include <kcore.h>
#endif

using json = nlohmann::json;
using KnishIO::Atom;
using KnishIO::Molecule;
using KnishIO::Wallet;

namespace {

constexpr size_t kExpectedCases = 16;

int failures = 0;

bool check(bool ok, const std::string& name, const std::string& detail = {}) {
    std::cout << (ok ? "  \033[0;32mPASS\033[0m " : "  \033[0;31mFAIL\033[0m ") << name;
    if (!ok && !detail.empty()) {
        std::cout << "\n       " << detail;
    }
    std::cout << '\n';
    if (!ok) {
        ++failures;
    }
    return ok;
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

std::string vectorsPath() {
    if (const char* env = std::getenv("KNISHIO_KCORE_PARITY_VECTORS")) {
        return env;
    }
#ifdef KNISHIO_KCORE_PARITY_VECTORS_PATH
    return KNISHIO_KCORE_PARITY_VECTORS_PATH;
#else
    return "fixtures/kcore-parity-vectors.json";
#endif
}

// "equal", or the first differing offset and both lengths.
std::string firstDifference(const std::string& got, const std::string& want) {
    if (got == want) {
        return "equal";
    }
    size_t at = 0;
    while (at < got.size() && at < want.size() && got[at] == want[at]) {
        ++at;
    }
    return "first difference at offset " + std::to_string(at) + " (got " + std::to_string(got.size()) +
           " chars, expected " + std::to_string(want.size()) + ")";
}

// The backend this binary runs on. With kcore linked, kcore must answer at runtime and agree
// with the SDK on the WOTS+ address of a vector wallet key.
bool checkBackend(const json& first) {
    const auto secret = first.at("secret").get<std::string>();
    const auto token = first.at("sourceToken").get<std::string>();
    const auto position = first.at("sourcePosition").get<std::string>();
    const auto key = Wallet::generateWalletKey(secret, token, position, 1);
#ifdef KNISHIO_HAVE_KCORE
    const int abi = kcore_abi_version();
    std::cout << "backend: kcore (ABI " << abi << ")\n";
    bool ok = check(abi > 0, "kcore answers kcore_abi_version()", "got " + std::to_string(abi));
    char address[64];
    const int rc = kcore_wots_address(key.c_str(), address);
    ok = check(rc == 0 && std::string(address, 64) == Wallet::generateWalletAddress(key),
               "kcore_wots_address() equals the SDK's address of a vector wallet key",
               "kcore rc " + std::to_string(rc)) && ok;
    return ok;
#else
    std::cout << "backend: pure (built without KNISHIO_USE_KCORE)\n";
    return check(Wallet::generateWalletAddress(key).size() == 64, "the pure path derives a wallet address");
#endif
}

bool verifyCase(const json& v, const std::string& name, const std::string& expectedHash) {
    bool ok = true;
    try {
        const Molecule molecule = Molecule::jsonToObject(v.at("molecule").dump());
        const std::string recomputed = Atom::hashAtomsBase17(molecule.atoms);
        ok = check(recomputed == expectedHash, name + ": (a) atoms hash to expected.molecularHash",
                   "molecularHash " + firstDifference(recomputed, expectedHash)) && ok;
        ok = check(molecule.molecularHash == expectedHash, name + ": (a) declared molecularHash is expected") && ok;
        const std::string verdict = outcome([&] { Molecule::verifyOts(molecule); });
        ok = check(verdict == "ok", name + ": (a) verifyOts() accepts the signature", verdict) && ok;
    } catch (const std::exception& e) {
        ok = check(false, name + ": (a) verify", std::string("threw: ") + e.what());
    }
    return ok;
}

bool resignCase(const json& v, const std::string& name, const std::string& expectedHash) {
    bool ok = true;
    try {
        const auto secret = v.at("secret").get<std::string>();
        const auto fragments = v.at("expected").at("otsFragments").get<std::vector<std::string>>();
        Molecule molecule = Molecule::jsonToObject(v.at("molecule").dump());
        // Clear the vector's signature so every byte compared below comes from this sign().
        molecule.molecularHash.clear();
        for (auto& atom : molecule.atoms) {
            atom.otsFragment.clear();
        }
        molecule.sourceWallet = std::make_shared<Wallet>(secret, v.at("sourceToken").get<std::string>(),
                                                         v.at("sourcePosition").get<std::string>(), 64, 1024,
                                                         v.at("otsVersion").get<int>());
        molecule.sign(secret);

        ok = check(molecule.molecularHash == expectedHash, name + ": (b) re-signed molecularHash",
                   firstDifference(molecule.molecularHash, expectedHash)) && ok;
        ok = check(molecule.atoms.size() == fragments.size(), name + ": (b) one otsFragment per atom",
                   "atoms " + std::to_string(molecule.atoms.size()) + ", expected " +
                       std::to_string(fragments.size())) && ok;
        for (size_t i = 0; i < molecule.atoms.size() && i < fragments.size(); i++) {
            ok = check(molecule.atoms[i].otsFragment == fragments[i],
                       name + ": (b) atoms[" + std::to_string(i) + "].otsFragment",
                       firstDifference(molecule.atoms[i].otsFragment, fragments[i])) && ok;
        }
    } catch (const std::exception& e) {
        ok = check(false, name + ": (b) re-sign", std::string("threw: ") + e.what());
    }
    return ok;
}

int run() {
    const std::string path = vectorsPath();
    std::ifstream file(path);
    if (!check(file.is_open(), "kcore-parity-vectors.json is readable", "cannot open " + path)) {
        return 1;
    }
    const json master = json::parse(file);
    const json& tests = master.at("vectors").at("molecules").at("tests");
    if (!check(tests.is_array() && tests.size() == kExpectedCases,
               "the master holds " + std::to_string(kExpectedCases) + " cases",
               "got " + std::to_string(tests.size()))) {
        return 1;
    }

    checkBackend(tests.front());

    size_t ran = 0;
    size_t passed = 0;
    for (const auto& v : tests) {
        const auto name = v.at("name").get<std::string>();
        const auto expectedHash = v.at("expected").at("molecularHash").get<std::string>();
        std::cout << "\n" << name << '\n';
        const bool verified = verifyCase(v, name, expectedHash);
        const bool resigned = resignCase(v, name, expectedHash);
        ++ran;
        if (verified && resigned) {
            ++passed;
        }
    }

    std::cout << "\nkcore parity vectors: " << passed << "/" << ran << " cases\n";
    check(ran == kExpectedCases, "all " + std::to_string(kExpectedCases) + " cases ran",
          "ran " + std::to_string(ran));
    return failures == 0 ? 0 : 1;
}

}  // namespace

int main() {
    try {
        run();
    } catch (const std::exception& e) {
        check(false, "kcore parity vectors", std::string("threw: ") + e.what());
    }
    std::cout << '\n';
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m\n";
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m\n";
    return 0;
}
