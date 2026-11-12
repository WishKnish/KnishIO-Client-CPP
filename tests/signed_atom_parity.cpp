/**
 * @file signed_atom_parity.cpp
 * @brief Signed atoms equal the JS reference byte for byte. Each digest literal below was printed
 *        by the JS SDK (KNISHIO_KCORE=off) for the same pinned inputs: secret =
 *        generateSecret('fleet-audit-2026-11'), wallet positions 'aa'x32 / 'bb'x32 / 'cc'x32, token
 *        TEST, OTS v1, ML-KEM-1024, createdAt '1700000000000' on every atom, hashed with
 *        Atom.hashAtoms. Also drives createToken / requestAuthToken against the loopback stub
 *        validator to check what the client builds around those atoms. No network.
 */
#include <algorithm>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "loopback_validator.h"
#include "utility.h"

using KnishIO::Atom;
using KnishIO::Molecule;
using KnishIO::Wallet;
using knishio_test::json;

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

Wallet wallet(const std::string& token, const std::string& position, int mlKem = 1024) {
    return Wallet(kSecret, token, position, 64, mlKem, 1);
}

std::string digest(Molecule& molecule) {
    for (auto& atom : molecule.atoms) {
        atom.createdAt = std::chrono::milliseconds(1700000000000LL);
    }
    return Atom::hashAtomsBase17(molecule.atoms);
}

void expectDigest(const std::string& name, const std::string& got, const std::string& js) {
    std::cout << "    " << name << " " << got << std::endl;
    check(got == js, name + " digest equals JS", "got " + got + ", JS " + js);
}

// The C atom carries the recipient wallet's batch id, the meta keeps the caller's order.
void tokenCreation() {
    Wallet source = wallet("USER", kPosA);
    Wallet remainder = wallet("USER", kPosC);
    Wallet recipient = wallet("TEST", kPosB);
    recipient.batchId = "B1";
    Molecule molecule("");
    molecule.sourceWallet = std::make_shared<Wallet>(source);
    molecule.remainderWallet = std::make_shared<Wallet>(remainder);
    molecule.initTokenCreation(source, recipient, "1000",
                               {{"name", "Fleet"}, {"fungibility", "stackable"}, {"supply", "limited"}, {"batchId", "B1"}});
    expectDigest("tokenCreation", digest(molecule), "015a0ff48g84b2ed492g77bcf241a3255d7994957gbe7427801b02286d8eafg5");
}

// A shadow-wallet claim's C atom carries the claimed wallet's batch id.
void shadowWalletClaim() {
    Wallet source = wallet("USER", kPosA);
    Wallet remainder = wallet("USER", kPosC);
    Wallet claimed = wallet("TEST", kPosB);
    claimed.batchId = "B1";
    Molecule molecule("");
    molecule.sourceWallet = std::make_shared<Wallet>(source);
    molecule.remainderWallet = std::make_shared<Wallet>(remainder);
    molecule.initShadowWalletClaim(source, claimed);
    expectDigest("shadowWalletClaim", digest(molecule), "03e97e6b21a8b1f51g60ead0627217bef310b1b50c389gg1gb087e966d12gd54");
}

// 2^53 - 1 (canonical vector atom_value_format.large_i64) moves without overflow.
void largeTransfer() {
    Wallet source = wallet("TEST", kPosA);
    source.balance = "9007199254740991";
    Wallet recipient = wallet("TEST", kPosB);
    Wallet remainder = wallet("TEST", kPosC);
    Molecule molecule("");
    molecule.sourceWallet = std::make_shared<Wallet>(source);
    molecule.remainderWallet = std::make_shared<Wallet>(remainder);
    try {
        molecule.initValue(source, recipient, remainder, "9007199254740991");
        std::string values;
        for (const auto& atom : molecule.atoms) {
            values += (values.empty() ? "" : ",") + atom.value;
        }
        check(values == "-9007199254740991,9007199254740991,0", "large transfer values equal JS", values);
        expectDigest("largeTransfer", digest(molecule), "029bcca23006d7cg31db77b15caef18616ffdfbgbfa76700304gf8efe5b2ccaf");
        const json serialized = json::parse(molecule.toJson());
        check(serialized["sourceWallet"]["balance"] == 9007199254740991LL, "toJson keeps the 64-bit source balance");
    } catch (const std::exception& e) {
        check(false, "large transfer builds", e.what());
    }
}

// The U atom carries exactly { encrypt, walletPubkey }; the batch id is SHAKE256 of hash + index.
void authorization() {
    Wallet source = wallet("AUTH", kPosA);
    Wallet remainder = wallet("USER", kPosC);
    Molecule molecule("");
    molecule.sourceWallet = std::make_shared<Wallet>(source);
    molecule.remainderWallet = std::make_shared<Wallet>(remainder);
    molecule.initAuthorization(source, false);
    const std::string hash = digest(molecule);
    expectDigest("authorization", hash, "0308f41249ef5c77fb3ag9417170026840c4ac34gc62d4268df581aa1b3b8a64");
    const std::string batchId = knishio::KnishIOClient::generateBatchId(hash, 0);
    check(batchId == "7ad9eeff09a1f55a19433cb6e89058c30e86aebad05cbffe7924280efaa708ef", "generateBatchId equals JS",
          batchId);
    check(knishio::KnishIOClient::generateBatchId(hash, 0) == batchId, "generateBatchId is deterministic");
}

std::string metaOf(const json& atom, const std::string& key) {
    for (const auto& item : atom["meta"]) {
        if (item.value("key", "") == key && item["value"].is_string()) {
            return item["value"].get<std::string>();
        }
    }
    return "<none>";
}

std::vector<std::string> metaKeys(const json& atom) {
    std::vector<std::string> keys;
    for (const auto& item : atom["meta"]) {
        keys.push_back(item.value("key", ""));
    }
    return keys;
}

size_t decodedLength(const std::string& base64) {
    return fromBase64(base64).size();
}

// The client around those atoms: createToken's meta order and batch id, and the ML-KEM set of
// every wallet a 768 client creates.
void clientOperations() {
    knishio_test::StubValidator stub;
    const std::string secret = knishio::KnishIOClient::generateSecret();
    auto client = knishio::KnishIOClient::Builder().uris({stub.uri()}).cellSlug("public").maxRetries(0)
                      .timeout(std::chrono::milliseconds(10000)).mlKemParameterSet(768).build();
    (void)client->requestAuthToken(secret).get();
    (void)client->createToken("TEST", 1000, {{"name", "Fleet"}, {"fungibility", "stackable"}, {"supply", "limited"}}, "B1")
        .get();
    const auto sent = stub.requests("ProposeMolecule");
    check(sent.size() == 2, "login + createToken proposed", std::to_string(sent.size()));
    if (sent.size() != 2) {
        return;
    }
    const json& auth = sent[0]["variables"]["molecule"]["atoms"].at(0);
    const std::vector<std::string> authKeys = metaKeys(auth);
    check(authKeys == std::vector<std::string>{"encrypt", "walletPubkey"}, "U atom meta is [encrypt, walletPubkey]",
          json(authKeys).dump());
    check(decodedLength(metaOf(auth, "walletPubkey")) == 1184, "768 client: U atom walletPubkey is 1184 bytes");

    const json& atoms = sent[1]["variables"]["molecule"]["atoms"];
    const json& c = atoms.at(0);
    const std::vector<std::string> keys = metaKeys(c);
    const std::vector<std::string> head(keys.begin(), keys.begin() + std::min<size_t>(4, keys.size()));
    check(head == std::vector<std::string>{"name", "fungibility", "supply", "batchId"},
          "createToken meta keeps the caller's order, then batchId", json(keys).dump());
    check(metaOf(c, "batchId") == "B1", "stackable token meta batchId is the caller's");
    check(c.value("batchId", json()).is_string() && c["batchId"] == "B1", "C atom batchId is the recipient wallet's",
          c.value("batchId", json()).dump());
    check(metaOf(c, "walletBatchId") == "B1", "walletBatchId meta is the recipient wallet's");
    check(decodedLength(metaOf(c, "walletPubkey")) == 1184, "768 client: C atom walletPubkey is 1184 bytes",
          std::to_string(decodedLength(metaOf(c, "walletPubkey"))));
    check(decodedLength(metaOf(atoms.at(1), "pubkey")) == 1184, "768 client: ContinuID pubkey is 1184 bytes",
          std::to_string(decodedLength(metaOf(atoms.at(1), "pubkey"))));
}

}  // namespace

int main() {
    std::cout << "Signed atoms vs the JS reference" << std::endl;
    tokenCreation();
    shadowWalletClaim();
    largeTransfer();
    authorization();
    std::cout << "\nClient operations (loopback stub)" << std::endl;
    clientOperations();

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
