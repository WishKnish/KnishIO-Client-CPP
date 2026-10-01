/**
 * @file create_meta_molecule.cpp
 * @brief The molecule KnishIOClient::createMeta proposes, built offline: an M-isotope atom
 *        carrying (metaType, metaId, meta) from the USER wallet, followed by the ContinuID
 *        I-isotope atom, signed and verified locally. No network.
 */
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "Molecule.h"
#include "Wallet.h"

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

}  // namespace

int main() {
    std::cout << "createMeta molecule (offline)" << std::endl;

    std::string secret;
    for (int i = 0; i < 128; i++) {
        secret += "0123456789abcdef";
    }
    const std::string position(64, 'a');
    const std::vector<std::pair<std::string, std::string>> meta = {{"sample", "7"}, {"note", "edge"}};

    Wallet source(secret, "USER", position, 64, 1024);
    Wallet remainder(secret, "USER", "", 64, 1024);

    Molecule mol("");
    mol.sourceWallet = std::make_shared<Wallet>(source);
    mol.remainderWallet = std::make_shared<Wallet>(remainder);
    mol.initMeta(source, meta, "EdgeBench", "run-1024-7");

    check(mol.atoms.size() == 2, "two atoms (M + I)", "got " + std::to_string(mol.atoms.size()));
    if (mol.atoms.size() == 2) {
        const auto& m = mol.atoms[0];
        check(m.isotope == "M", "atoms[0] isotope M", "got " + m.isotope);
        check(m.metaType == "EdgeBench", "atoms[0] metaType", "got " + m.metaType);
        check(m.metaId == "run-1024-7", "atoms[0] metaId", "got " + m.metaId);
        check(m.meta == meta, "atoms[0] meta pairs in order");
        check(m.token == "USER" && m.walletAddress == source.address && m.position == position,
              "atoms[0] from the USER source wallet");
        check(mol.atoms[1].isotope == "I", "atoms[1] isotope I (ContinuID)", "got " + mol.atoms[1].isotope);
    }

    mol.sign(secret);
    check(!mol.molecularHash.empty(), "signed: molecular hash set");
    check(Molecule::verifyMolecularHash(mol), "verifyMolecularHash");
    check(Molecule::verifyOts(mol), "verifyOts");
    check(Molecule::verifyContinuId(mol), "verifyContinuId");

    if (failures == 0) {
        std::cout << "ALL PASS" << std::endl;
        return 0;
    }
    std::cout << failures << " FAILED" << std::endl;
    return 1;
}
