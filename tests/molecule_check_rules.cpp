/**
 * @file molecule_check_rules.cpp
 * @brief Molecule::verify / Molecule::check follow JS CheckMolecule: the ContinuID atom, batchId,
 *        the M/T/C/U/I/R/P/A isotope rules and the V-transfer rules (same token as atoms[0], no
 *        negative value or self-transfer after atoms[0]); atoms are hashed and parsed in index
 *        order; atoms without a position or address (burn, shadow recipient) parse back.
 *        Every rejected molecule below is correctly signed and conserves value, so only the rule
 *        under test can reject it. No network.
 */
#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "AtomsNotFoundException.h"
#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "third_party/nlohmann/json.hpp"

using KnishIO::Atom;
using KnishIO::Molecule;
using KnishIO::Wallet;
using Meta = std::vector<std::pair<std::string, std::string>>;

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

const std::string kSecret = knishio::KnishIOClient::generateSecret("fleet-audit-2026-11");
const std::string kPosA(64, 'a');
const std::string kPosB(64, 'b');
const std::string kPosC(64, 'c');
const std::string kPosD(64, 'd');

std::string addressOf(const std::string& token, const std::string& position) {
    return Wallet(kSecret, token, position).address;
}

// Signs `atoms` with the wallet at atoms[0] (token, position).
Molecule signedMolecule(const std::vector<Atom>& atoms) {
    Molecule molecule("");
    molecule.sourceWallet = std::make_shared<Wallet>(kSecret, atoms.front().token, atoms.front().position);
    molecule.atoms = atoms;
    molecule.sign(kSecret);
    return molecule;
}

Atom vAtom(const std::string& token, const std::string& position, const std::string& address,
           const std::string& value, int index, const std::string& batchId = {}) {
    return Atom(position, address, "V", token, value, batchId, index == 0 ? "" : "walletBundle",
                index == 0 ? "" : std::string(64, 'e'), {}, "", index);
}

// The I atom the USER wallet at kPosD would add.
Atom continuIdAtom(int index) {
    return Atom(kPosD, addressOf("USER", kPosD), "I", "USER", {}, {}, "walletBundle",
                Wallet::generateBundleHash(kSecret), {{"previousPosition", kPosA}}, "", index);
}

std::string checkError(const Molecule& molecule) {
    try {
        Molecule::check(molecule);
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

void expectRejected(const std::string& name, const Molecule& molecule) {
    const bool verified = Molecule::verify(molecule);
    const std::string error = checkError(molecule);
    check(!verified && !error.empty(), name + " is rejected",
          "verify=" + std::string(verified ? "true" : "false") + " check error=\"" + error + "\"");
    if (!error.empty()) {
        std::cout << "       (" << error << ")" << std::endl;
    }
}

void expectAccepted(const std::string& name, const Molecule& molecule) {
    const bool verified = Molecule::verify(molecule);
    const std::string error = checkError(molecule);
    check(verified && error.empty(), name + " verifies",
          "verify=" + std::string(verified ? "true" : "false") + " check error=\"" + error + "\"");
}

void transferRules() {
    std::cout << "V-transfer rules" << std::endl;
    const std::string src = addressOf("TEST", kPosA);
    const std::string other = addressOf("TEST", kPosB);
    const std::string other2 = addressOf("TEST", kPosC);

    expectAccepted("transfer -1000 / +400 / +600",
                   signedMolecule({vAtom("TEST", kPosA, src, "-1000", 0), vAtom("TEST", kPosB, other, "400", 1),
                                   vAtom("TEST", kPosC, other2, "600", 2)}));
    expectRejected("negative recipient -500 / -500 / +1000",
                   signedMolecule({vAtom("TEST", kPosA, src, "-500", 0), vAtom("TEST", kPosB, other, "-500", 1),
                                   vAtom("TEST", kPosC, other2, "1000", 2)}));
    expectRejected("self-transfer -100 / +10 to the source address / +90",
                   signedMolecule({vAtom("TEST", kPosA, src, "-100", 0), vAtom("TEST", kPosB, src, "10", 1),
                                   vAtom("TEST", kPosC, other2, "90", 2)}));
    expectRejected("mixed tokens (each token balances on its own)",
                   signedMolecule({vAtom("TEST", kPosA, src, "-100", 0), vAtom("TEST", kPosB, other, "100", 1),
                                   vAtom("OTHER", kPosC, other2, "-50", 2), vAtom("OTHER", kPosD, other, "50", 3)}));
    expectRejected("non-numeric value \"abc\"",
                   signedMolecule({vAtom("TEST", kPosA, src, "-100", 0), vAtom("TEST", kPosB, other, "abc", 1),
                                   vAtom("TEST", kPosC, other2, "100", 2)}));
    expectRejected("batched transfer whose remainder has another batch id",
                   signedMolecule({vAtom("TEST", kPosA, src, "-100", 0, "batch-1"),
                                   vAtom("TEST", kPosB, other, "10", 1, "batch-2"),
                                   vAtom("TEST", kPosC, other2, "90", 2, "batch-3")}));
    expectAccepted("batched transfer keeping the batch on the remainder",
                   signedMolecule({vAtom("TEST", kPosA, src, "-100", 0, "batch-1"),
                                   vAtom("TEST", kPosB, other, "10", 1, "batch-2"),
                                   vAtom("TEST", kPosC, other2, "90", 2, "batch-1")}));
}

void isotopeRules() {
    std::cout << "\nIsotope rules" << std::endl;
    const std::string user = addressOf("USER", kPosA);
    const std::string bundle = Wallet::generateBundleHash(kSecret);

    expectRejected("USER-signed M molecule without its ContinuID (I) atom",
                   signedMolecule({Atom(kPosA, user, "M", "USER", {}, {}, "note", "n1", {{"text", "x"}}, "", 0)}));
    expectAccepted("USER-signed M molecule with its ContinuID atom",
                   signedMolecule({Atom(kPosA, user, "M", "USER", {}, {}, "note", "n1", {{"text", "x"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("M atom with a forged token",
                   signedMolecule({Atom(kPosA, addressOf("TEST", kPosA), "M", "TEST", {}, {}, "note", "n1",
                                        {{"text", "x"}}, "", 0)}));
    expectRejected("M atom whose policy names a key missing from the meta",
                   signedMolecule({Atom(kPosA, user, "M", "USER", {}, {}, "note", "n1",
                                        {{"text", "x"}, {"readPolicy", R"({"title":["all"]})"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("M atom whose policy value is neither a bundle hash nor all/self",
                   signedMolecule({Atom(kPosA, user, "M", "USER", {}, {}, "note", "n1",
                                        {{"text", "x"}, {"readPolicy", R"({"text":["everyone"]})"}}, "", 0),
                                   continuIdAtom(1)}));
    expectAccepted("M atom with a valid policy",
                   signedMolecule({Atom(kPosA, user, "M", "USER", {}, {}, "note", "n1",
                                        {{"text", "x"}, {"readPolicy", R"({"text":["self",")" + bundle + R"("]})"}},
                                        "", 0),
                                   continuIdAtom(1)}));
    expectRejected("C atom with a forged token",
                   signedMolecule({Atom(kPosA, addressOf("TEST", kPosA), "C", "TEST", "100", {}, "token", "NEW",
                                        {}, "", 0)}));
    expectRejected("U atom with a forged token",
                   signedMolecule({Atom(kPosA, addressOf("FOO", kPosA), "U", "FOO", {}, {}, {}, {},
                                        {{"encrypt", "false"}}, "", 0)}));
    expectRejected("I atom with a forged token",
                   signedMolecule({Atom(kPosA, addressOf("AUTH", kPosA), "U", "AUTH", {}, {}, {}, {},
                                        {{"encrypt", "false"}}, "", 0),
                                   Atom(kPosD, addressOf("TEST", kPosD), "I", "TEST", {}, {}, "walletBundle", bundle,
                                        {}, "", 1)}));
    expectRejected("T atom without a token meta",
                   signedMolecule({Atom(kPosA, user, "T", "USER", {}, {}, "walletBundle", bundle, {{"amount", "1"}},
                                        "", 0),
                                   continuIdAtom(1)}));
    expectAccepted("T atom with a token meta and no metaType",
                   signedMolecule({Atom(kPosA, user, "T", "USER", {}, {}, {}, {}, {{"token", "TEST"}, {"amount", "1"}},
                                        "", 0),
                                   continuIdAtom(1)}));
    const std::string rule = R"([{"condition":[{"key":"k","value":"v","comparison":"=="}],"callback":[{"action":"reject"}]}])";
    expectAccepted("JS-format R molecule (rule array + read/write policy)",
                   signedMolecule({Atom(kPosA, user, "R", "USER", {}, {}, "note", "n1",
                                        {{"rule", rule}, {"policy", R"({"read":{},"write":{}})"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("R atom whose policy mixes rules with policies",
                   signedMolecule({Atom(kPosA, user, "R", "USER", {}, {}, "note", "n1",
                                        {{"rule", rule}, {"policy", R"({"read":{},"rule":{}})"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("R atom whose rule has no callback",
                   signedMolecule({Atom(kPosA, user, "R", "USER", {}, {}, "note", "n1",
                                        {{"rule", R"([{"condition":[{"key":"k","value":"v","comparison":"=="}]}])"}},
                                        "", 0),
                                   continuIdAtom(1)}));
    expectRejected("R atom with an empty rule list",
                   signedMolecule({Atom(kPosA, user, "R", "USER", {}, {}, "note", "n1", {{"rule", "[]"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("P atom without peerHost",
                   signedMolecule({Atom(kPosA, user, "P", "USER", {}, {}, {}, {}, {{"peer", "x"}}, "", 0),
                                   continuIdAtom(1)}));
    expectAccepted("P atom with peerHost",
                   signedMolecule({Atom(kPosA, user, "P", "USER", {}, {}, {}, {}, {{"peerHost", "node.example"}}, "", 0),
                                   continuIdAtom(1)}));
    expectRejected("A atom without an action meta",
                   signedMolecule({Atom(kPosA, user, "A", "USER", {}, {}, "note", "n1", {{"note", "x"}}, "", 0),
                                   continuIdAtom(1)}));
    expectAccepted("A atom with metaType, metaId and action",
                   signedMolecule({Atom(kPosA, user, "A", "USER", {}, {}, "note", "n1", {{"action", "append"}}, "", 0),
                                   continuIdAtom(1)}));
}

void indexOrder() {
    std::cout << "\nIndex order and parsing" << std::endl;
    const std::string src = addressOf("TEST", kPosA);
    const Molecule transfer = signedMolecule({vAtom("TEST", kPosA, src, "-1000", 0),
                                              vAtom("TEST", kPosB, addressOf("TEST", kPosB), "400", 1),
                                              vAtom("TEST", kPosC, addressOf("TEST", kPosC), "600", 2)});
    std::vector<Atom> reversed(transfer.atoms.rbegin(), transfer.atoms.rend());
    const std::string reversedHash = Atom::hashAtomsBase17(reversed);
    check(reversedHash == transfer.molecularHash, "a reversed atom array hashes in index order",
          reversedHash + " != " + transfer.molecularHash);

    nlohmann::json json = nlohmann::json::parse(transfer.toJson());
    std::reverse(json["atoms"].begin(), json["atoms"].end());
    try {
        const Molecule parsed = Molecule::jsonToObject(json.dump());
        check(parsed.atoms.front().index == 0 && parsed.atoms.back().index == 2,
              "jsonToObject sorts the atoms by index");
        check(Molecule::verify(parsed), "a molecule served with its atoms reversed verifies");
    } catch (const std::exception& e) {
        check(false, "jsonToObject of a reversed atom array", e.what());
    }

    // A burn: the burn-target atom has no position or address.
    Wallet source(kSecret, "TEST", kPosA);
    source.balance = "1000";
    Wallet burn(kSecret, "TEST", kPosB);
    burn.bundle = std::string(64, '0');
    burn.position.clear();
    burn.address.clear();
    Wallet remainder(kSecret, "TEST", kPosC);
    Molecule burnMolecule("");
    burnMolecule.sourceWallet = std::make_shared<Wallet>(source);
    burnMolecule.remainderWallet = std::make_shared<Wallet>(remainder);
    burnMolecule.initValue(source, burn, remainder, "100");
    burnMolecule.sign(kSecret);
    try {
        const Molecule parsed = Molecule::jsonToObject(burnMolecule.toJson());
        check(parsed.atoms.size() == 3 && Molecule::verify(parsed), "a burn molecule from toJson() parses back and verifies");
    } catch (const std::exception& e) {
        check(false, "a burn molecule from toJson() parses back", e.what());
    }

    nlohmann::json nullAtom = {{"position", nullptr}, {"walletAddress", nullptr}, {"isotope", "V"},
                               {"token", nullptr}, {"value", "1"}, {"index", 1}, {"createdAt", "1"}};
    try {
        const Atom atom = Atom::jsonToObject(nullAtom.dump());
        check(atom.position.empty() && atom.walletAddress.empty() && atom.token.empty(),
              "Atom::jsonToObject reads null position, walletAddress and token as absent");
    } catch (const std::exception& e) {
        check(false, "Atom::jsonToObject with null position, walletAddress and token", e.what());
    }

    bool threw = false;
    try {
        (void)Atom::hashAtoms({});
    } catch (const AtomsNotFoundException&) {
        threw = true;
    } catch (const std::exception&) {
    }
    check(threw, "hashAtoms({}) throws AtomsNotFoundException");
}

}  // namespace

int main() {
    transferRules();
    isotopeRules();
    indexOrder();

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
