/**
 * @file client_operations.cpp
 * @brief Client, wallet and response methods that failed or did the wrong thing: a passphrase
 *        secret, createMolecule's wallets and OTS version, queryWallets' token filter,
 *        decryptMyMessage, the validator key in an authorization response, QueryBalance's
 *        response, setSecret leaving the replaced secret in freed memory, and the shadow
 *        recipient wallets of the value transfers. Driven against the loopback stub validator; no
 *        network. `leaks` / LSan runs of this binary also cover the per-request header list.
 */
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>
#if defined(__APPLE__)
#include <malloc/malloc.h>
#else
#include <malloc.h>
#endif

#include "Atom.h"
#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "crypto.h"
#include "exception/KnishIOException.h"
#include "http/GraphQLClient.h"
#include "loopback_validator.h"
#include "query/QueryBalance.h"
#include "response/Response.h"
#include "utility.h"

using KnishIO::Atom;
using KnishIO::Molecule;
using KnishIO::Wallet;
using knishio_test::json;

// Freed-block watch (setSecret test): every heap block, std::string buffers included, is freed
// through this replacement of the global operator delete. While armed it counts the freed blocks
// that still hold the watched bytes, i.e. a secret the client dropped without wiping it.
namespace freed_watch {
std::atomic<bool> armed{false};
std::atomic<int> hits{0};
char needle[64];

size_t blockSize(void* p) {
#if defined(__APPLE__)
    return malloc_size(p);
#else
    return malloc_usable_size(p);
#endif
}

void inspect(void* p) {
    if (p == nullptr || !armed.load()) return;
    const auto* bytes = static_cast<const char*>(p);
    const size_t size = blockSize(p);
    if (size >= sizeof(needle) && std::search(bytes, bytes + size, needle, needle + sizeof(needle)) != bytes + size) {
        hits.fetch_add(1);
    }
}

// Watches the last 64 bytes of `watched` (at least 64 bytes long).
void start(const std::string& watched) {
    std::copy_n(watched.end() - sizeof(needle), sizeof(needle), needle);
    hits = 0;
    armed = true;
}

int stop() {
    armed = false;
    return hits.load();
}
}  // namespace freed_watch

void* operator new(std::size_t size) {
    if (void* p = std::malloc(size == 0 ? 1 : size)) return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept {
    freed_watch::inspect(p);
    std::free(p);
}
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }

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

std::unique_ptr<knishio::KnishIOClient> clientFor(const knishio_test::StubValidator& stub) {
    return knishio::KnishIOClient::Builder().uris({stub.uri()}).cellSlug("public").maxRetries(0)
        .timeout(std::chrono::milliseconds(10000)).build();
}

void passphraseSecret() {
    knishio_test::StubValidator stub;
    auto client = clientFor(stub);
    const std::string passphrase = "correct horse battery staple";
    try {
        client->setSecret(passphrase);
        check(client->getBundle() == shake256Hex(passphrase, 256), "a passphrase secret is accepted (bundle = SHAKE256)");
    } catch (const std::exception& e) {
        check(false, "a passphrase secret is accepted", e.what());
    }
}

void createMolecule() {
    knishio_test::StubValidator stub;
    auto client = clientFor(stub);
    const std::string secret = knishio::KnishIOClient::generateSecret();
    (void)client->requestAuthToken(secret).get();
    try {
        auto molecule = client->createMolecule();
        check(molecule->sourceWallet != nullptr && molecule->remainderWallet != nullptr,
              "createMolecule sets the source and remainder wallets");
        check(molecule->bundle == Wallet::generateBundleHash(secret), "createMolecule sets the bundle");
        check(molecule->cellSlug == "public", "createMolecule takes the client's cell slug");
        check(molecule->signingOtsVersion() == client->getOtsVersion(),
              "the molecule signs at the client's OTS version",
              std::to_string(molecule->signingOtsVersion()) + " != " + std::to_string(client->getOtsVersion()));
        molecule->initMeta(*molecule->sourceWallet, {{"note", "x"}}, "note", "n1");
        molecule->sign(secret);
        Molecule::check(*molecule);
        check(true, "a createMolecule molecule signs and passes Molecule::check");
    } catch (const std::exception& e) {
        check(false, "createMolecule builds a signable molecule", e.what());
    }
}

void queryWalletsFiltersToken() {
    knishio_test::StubValidator stub;
    auto client = clientFor(stub);
    (void)client->requestAuthToken(knishio::KnishIOClient::generateSecret()).get();
    stub.setRawReply(json{{"data", {{"wallets", json::array({
        {{"address", "a1"}, {"tokenSlug", "ALPHA"}, {"position", "p1"}, {"amount", "1"}},
        {{"address", "b1"}, {"tokenSlug", "BETA"}, {"position", "p2"}, {"amount", "2"}},
    })}}}}.dump());
    const auto wallets = client->queryWallets(std::nullopt, std::string("ALPHA")).get()->getWallets();
    check(wallets.size() == 1 && wallets[0].token == "ALPHA", "queryWallets filters by token",
          std::to_string(wallets.size()) + " wallets");
    const auto all = client->queryWallets().get()->getWallets();
    check(all.size() == 2, "queryWallets without a token returns every wallet");
}

void decryptMyMessage() {
    Wallet wallet(knishio::KnishIOClient::generateSecret(), "USER");
    try {
        const std::string encrypted = encryptMessage("hello", wallet.pubkey);
        check(wallet.decryptMyMessage(encrypted) == "hello", "decryptMyMessage round-trips");
    } catch (const std::exception& e) {
        check(false, "decryptMyMessage round-trips", e.what());
    }
    check(wallet.pubkey.size() == 32 && wallet.mlkem_public_key.size() == 1568,
          "the NaCl public key and the ML-KEM public key stay separate",
          std::to_string(wallet.pubkey.size()) + " / " + std::to_string(wallet.mlkem_public_key.size()));
}

void responses() {
    knishio::response::ResponseRequestAuthorization auth;
    auth.setData({{"ProposeMolecule", {{"payload", R"({"token":"jwt","key":"VALIDATOR-KEY"})"}}}});
    check(auth.getPublicKey() == "VALIDATOR-KEY", "ResponseRequestAuthorization reads the validator key from \"key\"",
          auth.getPublicKey());

    knishio::http::GraphQLClient http("http://127.0.0.1:9/graphql", 1000, 0);
    knishio::query::QueryBalance query(&http);
    try {
        auto response = query.createResponse({{"data", {{"Balance", {{"address", "addr"}, {"amount", "5"},
                                                                     {"position", nullptr}, {"batchId", nullptr}}}}}});
        const auto balance = dynamic_cast<knishio::response::ResponseBalance&>(*response).getBalance();
        check(balance.has_value() && balance->amount == "5" && balance->position.empty(),
              "QueryBalance::createResponse unwraps data and tolerates null fields");
    } catch (const std::exception& e) {
        check(false, "QueryBalance::createResponse", e.what());
    }
}

// setSecret replaces the secret: the new bundle, the empty-secret refusal, a molecule signed under
// the new secret, and no freed heap block left holding the old secret. Covers a shorter
// replacement (the old buffer is reused) and a longer one (the old buffer is freed).
void setSecretReplacesAndWipes() {
    {
        // The watch itself: a freed std::string buffer that holds the bytes is seen.
        const std::string marker = "freed-watch control " + std::string(60, 'w');
        freed_watch::start(marker);
        {
            std::string probe(marker);
            asm volatile("" : : "r"(probe.data()) : "memory");
        }
        check(freed_watch::stop() >= 1, "the freed-block watch sees a freed std::string buffer");
    }

    struct Case {
        std::string label;
        std::string first;
        std::string second;
    };
    const std::vector<Case> cases = {
        {"a 2048-hex secret replaced by a passphrase",
         knishio::KnishIOClient::generateSecret(std::string("cpp-1 first secret")), "correct horse battery staple"},
        {"a passphrase replaced by a 2048-hex secret", "cpp-1 passphrase " + std::string(60, 'p'),
         knishio::KnishIOClient::generateSecret(std::string("cpp-1 second secret"))},
    };
    for (const auto& c : cases) {
        std::cout << "\nsetSecret: " << c.label << std::endl;
        knishio_test::StubValidator stub;
        auto client = clientFor(stub);
        client->setSecret(c.first);
        freed_watch::start(c.first);

        client->setSecret(c.second);
        const std::string secondBundle = Wallet::generateBundleHash(c.second);
        check(client->getBundle() == secondBundle, "getBundle() is the new secret's bundle");
        bool refused = false;
        try {
            client->setSecret("");
        } catch (const knishio::KnishIOException&) {
            refused = true;
        }
        check(refused, "setSecret(\"\") throws KnishIOException");
        check(client->getBundle() == secondBundle, "the refused call keeps the new secret's bundle");
        try {
            auto molecule = client->createMolecule();
            molecule->initMeta(*molecule->sourceWallet, {{"note", "x"}}, "note", "n1");
            molecule->sign(c.second);
            Molecule::check(*molecule);
            check(molecule->bundle == secondBundle && molecule->sourceWallet->bundle == secondBundle,
                  "a molecule created afterwards is signed under the new secret and passes Molecule::check");
        } catch (const std::exception& e) {
            check(false, "a molecule created afterwards signs under the new secret", e.what());
        }

        client.reset();
        const int hits = freed_watch::stop();
        check(hits == 0, "no freed heap block still holds the replaced secret",
              std::to_string(hits) + " freed block(s) held its last 64 bytes");
    }
}

// A client logged in to its own stub with a pinned secret, so every molecule byte the client does
// not draw at random is fixed.
struct PinnedSession {
    knishio_test::StubValidator stub;
    std::string secret = knishio::KnishIOClient::generateSecret(std::string("cpp-2 shadow recipients"));
    std::string bundle = Wallet::generateBundleHash(secret);
    std::unique_ptr<knishio::KnishIOClient> client;

    PinnedSession() : client(clientFor(stub)) { (void)client->requestAuthToken(secret).get(); }

    [[nodiscard]] json row(const std::string& token, const std::string& position, const std::string& amount,
                           const std::vector<std::string>& units = {}) const {
        json unitRows = json::array();
        for (const auto& id : units) unitRows.push_back({{"id", id}, {"name", id}, {"metas", json::object()}});
        return {{"position", position}, {"address", Wallet(secret, token, position).address}, {"tokenSlug", token},
                {"amount", amount}, {"pubkey", nullptr}, {"batchId", nullptr}, {"bundleHash", bundle},
                {"tokenUnits", unitRows}};
    }

    // The one molecule proposed after the login.
    [[nodiscard]] json sent() const {
        const auto all = stub.requests("ProposeMolecule");
        return all.size() == 2 ? all[1]["variables"]["molecule"] : json(nullptr);
    }
};

// Wallet::createShadow: a wallet for another bundle with no key material.
void createShadowWallet() {
    std::cout << "\nWallet::createShadow" << std::endl;
    const std::string bundle = Wallet::generateBundleHash(knishio::KnishIOClient::generateSecret());
    const Wallet w = Wallet::createShadow(bundle, "CRZY", "batch-1", 768, 2);
    check(w.bundle == bundle && w.token == "CRZY" && w.batchId == "batch-1", "bundle, token and batch id are set");
    check(w.mlkem_parameter_set == 768 && w.ots_version == 2, "parameter set and OTS version are set");
    check(w.key.empty() && w.privkey.empty() && w.pubkey.empty() && w.mlkem_public_key.empty()
              && w.mlkem_private_key.empty() && w.position.empty() && w.address.empty(),
          "no key, NaCl or ML-KEM keys, position or address");
    const Wallet d = Wallet::createShadow(bundle);
    check(d.token == "USER" && d.batchId.empty() && d.mlkem_parameter_set == 1024 && d.ots_version == 1,
          "defaults: USER, no batch id, ML-KEM-1024, OTS version 1");
    auto throwsInvalid = [](const std::function<void()>& op) {
        try {
            op();
        } catch (const std::invalid_argument&) {
            return true;
        } catch (...) {
            return false;
        }
        return false;
    };
    check(throwsInvalid([] { (void)Wallet::createShadow(""); }), "an empty bundle throws std::invalid_argument");
    check(throwsInvalid([&] { (void)Wallet::createShadow(bundle, "CRZY", "", 512); }),
          "ML-KEM parameter set 512 throws std::invalid_argument");
    check(throwsInvalid([&] { (void)Wallet::createShadow(bundle, "CRZY", "", 1024, 3); }),
          "OTS version 3 throws std::invalid_argument");
}

std::string atomField(const json& atom, const std::string& key) {
    return atom.contains(key) && atom[key].is_string() ? atom[key].get<std::string>() : "";
}

// The molecular hash with the values the client draws at random pinned: every createdAt, and the
// position and address of the remainder (the last atom). Every other byte is the client's.
std::string pinnedHash(json molecule) {
    auto& atoms = molecule["atoms"];
    for (auto& atom : atoms) atom["createdAt"] = "1700000000000";
    atoms.back()["position"] = std::string(64, 'a');
    atoms.back()["walletAddress"] = std::string(64, 'b');
    return Atom::hashAtomsBase17(Molecule::jsonToObject(molecule.dump()).atoms);
}

// The recipients of transferToken, transferTokens, burnToken, withdrawBufferToken and fuseToken
// to another bundle are shadow wallets; the molecules keep their bytes. The expected hashes were
// captured from the client before the recipients became Wallet::createShadow wallets (they
// derived a full key then).
void shadowRecipientMolecules() {
    const std::string own = Wallet::generateBundleHash(
        knishio::KnishIOClient::generateSecret(std::string("cpp-2 shadow recipients")));
    const std::string other1 = Wallet::generateBundleHash("cpp-2 recipient one");
    const std::string other2 = Wallet::generateBundleHash("cpp-2 recipient two");
    const std::map<std::string, std::string> expected = {
        {"transferToken", "04453f9c5198f6411bb9a3gdbd9a6e95fe8af1b91a5a8f01gf55917c054b3b82"},
        {"transferTokens", "02309713cf83fc80ae38fec977c22e86792d5035g2e20757b601cd9af5cacgd5"},
        {"burnToken", "04ac6dc7526a69939ecb9ad2a6733cbe108ccc60g1bf3fe59daff3257c2164b1"},
        {"withdrawBufferToken", "04cff583159897e026c464418d671e6686049cd00g15e498dg5ag7ab8cb960ba"},
        {"fuseToken", "04428e7382c7d62dg1082681e3gfc701ee6ca8ff6begg944ed6ea1ga1ga5aa92"},
    };
    auto run = [&](const std::string& name, const std::function<void(PinnedSession&)>& setUp,
                   const std::function<void(PinnedSession&)>& op,
                   const std::function<void(const json&)>& recipients) {
        std::cout << "\n" << name << ": shadow recipients, pinned inputs" << std::endl;
        PinnedSession s;
        setUp(s);
        try {
            op(s);
        } catch (const std::exception& e) {
            check(false, name + " proposes a molecule", e.what());
            return;
        }
        const json molecule = s.sent();
        if (!molecule.is_object()) {
            check(false, name + " proposes one molecule");
            return;
        }
        recipients(molecule["atoms"]);
        check(Molecule::verify(Molecule::jsonToObject(molecule.dump())), "the proposed molecule passes Molecule::verify");
        const std::string hash = pinnedHash(molecule);
        std::cout << "  captured " << name << " " << hash << std::endl;
        check(hash == expected.at(name), "the molecular hash equals the one captured before the change",
              hash + " != " + expected.at(name));
    };
    auto shadowAtom = [](const json& atom, const std::string& bundle, const std::string& batchId,
                         const std::string& label) {
        const bool batchOk = batchId.empty() ? atomField(atom, "batchId").empty() : atomField(atom, "batchId") == batchId;
        check(atomField(atom, "position").empty() && atomField(atom, "walletAddress").empty()
                  && atomField(atom, "metaId") == bundle && batchOk,
              label + ": no position or address, metaId = its bundle, batch id " + (batchId.empty() ? "none" : batchId));
    };

    run("transferToken",
        [](PinnedSession& s) { s.stub.setBalance(s.row("FUNG", std::string(64, '1'), "100")); },
        [&](PinnedSession& s) { (void)s.client->transferToken(other1, "FUNG", 10, "batch-one").get(); },
        [&](const json& atoms) { shadowAtom(atoms[1], other1, "batch-one", "recipient atom"); });

    run("transferTokens",
        [](PinnedSession& s) { s.stub.setBalance(s.row("STK", std::string(64, '2'), "4", {"U1", "U2", "U3", "U4"})); },
        [&](PinnedSession& s) {
            (void)s.client->transferTokens("STK", {{other1, 0, "batch-one", {"U1", "U3"}},
                                                   {other2, 0, "batch-two", {"U2"}}}).get();
        },
        [&](const json& atoms) {
            shadowAtom(atoms[1], other1, "batch-one", "first recipient atom");
            shadowAtom(atoms[2], other2, "batch-two", "second recipient atom");
        });

    run("burnToken",
        [](PinnedSession& s) { s.stub.setBalance(s.row("FUNG", std::string(64, '3'), "100")); },
        [](PinnedSession& s) { (void)s.client->burnToken("FUNG", 7).get(); },
        [&](const json& atoms) { shadowAtom(atoms[1], std::string(64, '0'), "", "burn atom"); });

    run("withdrawBufferToken",
        [](PinnedSession& s) {
            s.stub.setBalance(s.row("BUF", std::string(64, '4'), "900"), s.row("BUF", std::string(64, '5'), "50"));
        },
        [](PinnedSession& s) { (void)s.client->withdrawBufferToken("BUF", 20).get(); },
        [&](const json& atoms) { shadowAtom(atoms[1], own, "", "recipient atom"); });

    run("fuseToken",
        [](PinnedSession& s) { s.stub.setBalance(s.row("STK", std::string(64, '6'), "3", {"V1", "V2", "V3"})); },
        [&](PinnedSession& s) { (void)s.client->fuseToken(other2, "STK", "FUSED", {"V1", "V3"}).get(); },
        [&](const json& atoms) { shadowAtom(atoms[2], other2, "", "fusion atom"); });
}

}  // namespace

int main() {
    std::cout << "Client operations (loopback stub)" << std::endl;
    passphraseSecret();
    createMolecule();
    queryWalletsFiltersToken();
    decryptMyMessage();
    responses();
    setSecretReplacesAndWipes();
    createShadowWallet();
    shadowRecipientMolecules();

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
