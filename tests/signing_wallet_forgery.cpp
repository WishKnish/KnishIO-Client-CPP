/**
 * @file signing_wallet_forgery.cpp
 * @brief The OTS check must compare the recovered signing address with atoms[0].walletAddress
 *        only. A `signingWallet` meta on atoms[0] must not redirect it to another wallet.
 *
 * Fixture: tests/fixtures/signing-wallet-forgery.json, built by the published JS SDK 1.2.1 and
 * shared byte-for-byte by all eight SDKs. `genuine` is an M+I meta molecule signed normally by
 * wallet B. `forged` is the same build with atoms[0].walletAddress set to the victim A, B's
 * one-time signature, and a `signingWallet` meta on atoms[0] naming B. JS 1.2.1 accepts both;
 * a verifier that honours the meta accepts a molecule claiming A's address that A never signed.
 *
 * C++ has no SignatureMismatchException: Molecule::verifyOts() returning false is the SDK's
 * signature-mismatch verdict, and Molecule::verify() folds it in.
 */
#include <fstream>
#include <iostream>
#include <string>

#include "Molecule.h"
#include "third_party/nlohmann/json.hpp"

using json = nlohmann::json;
using KnishIO::Molecule;

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

std::string verdicts(const Molecule& molecule) {
    return "verifyMolecularHash=" + std::string(Molecule::verifyMolecularHash(molecule) ? "true" : "false") +
           " verifyTokenIsotopeV=" + std::string(Molecule::verifyTokenIsotopeV(molecule) ? "true" : "false") +
           " verifyOts=" + std::string(Molecule::verifyOts(molecule) ? "true" : "false");
}

json loadFixture() {
    // Baked in by tests/CMakeLists.txt as the path beside this file, so the working directory
    // does not matter. A missing fixture is a hard failure: skipping would pass having asserted
    // nothing.
    std::ifstream f(KNISHIO_FORGERY_FIXTURE_PATH);
    if (!f.is_open()) {
        throw std::runtime_error(std::string("fixture not found: ") + KNISHIO_FORGERY_FIXTURE_PATH);
    }
    return json::parse(f);
}

}  // namespace

int main() {
    std::cout << "signingWallet forgery fixture" << std::endl;

    json fixture;
    try {
        fixture = loadFixture();
    } catch (const std::exception& e) {
        std::cout << "  \033[0;31mFAIL\033[0m " << e.what() << std::endl;
        return 1;
    }

    const auto victimAddress = fixture.at("victimAddress").get<std::string>();
    const auto attackerAddress = fixture.at("attackerAddress").get<std::string>();

    try {
        const Molecule genuine = Molecule::jsonToObject(fixture.at("genuine").dump());
        check(Molecule::verify(genuine), "genuine: loads and Molecule::verify() passes", verdicts(genuine));
    } catch (const std::exception& e) {
        check(false, "genuine: loads and Molecule::verify() passes", std::string("threw: ") + e.what());
    }

    try {
        const Molecule forged = Molecule::jsonToObject(fixture.at("forged").dump());
        const auto& claimed = forged.atoms.front();

        check(claimed.walletAddress == victimAddress,
              "forged: atoms[0].walletAddress is the fixture's victimAddress",
              "got " + claimed.walletAddress + ", expected " + victimAddress);

        bool carriesOverride = false;
        for (const auto& kv : claimed.meta) {
            if (kv.first == "signingWallet" && json::parse(kv.second).value("address", "") == attackerAddress) {
                carriesOverride = true;
            }
        }
        check(carriesOverride, "forged: atoms[0] meta carries a signingWallet naming the attacker");

        // The hash is intact, so the only thing that can reject it is the signature check.
        check(Molecule::verifyMolecularHash(forged), "forged: molecular hash is intact", verdicts(forged));

        // The signature is B's genuine one-time signature over this hash: pointed at B's address
        // it verifies. So a rejection below is the address mismatch, not a malformed signature.
        Molecule asAttacker = forged;
        asAttacker.atoms.front().walletAddress = attackerAddress;
        check(Molecule::verifyOts(asAttacker), "forged: the OTS is the attacker's valid signature over this hash");

        check(!Molecule::verifyOts(forged),
              "forged: Molecule::verifyOts() rejects it (signature mismatch against the victim address)",
              "the signingWallet meta redirected the address check to the attacker");
        check(!Molecule::verify(forged), "forged: Molecule::verify() fails", verdicts(forged));
    } catch (const std::exception& e) {
        check(false, "forged: loads and is rejected", std::string("threw: ") + e.what());
    }

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
