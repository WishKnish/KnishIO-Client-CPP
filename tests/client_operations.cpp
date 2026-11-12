/**
 * @file client_operations.cpp
 * @brief Client, wallet and response methods that failed or did the wrong thing: a passphrase
 *        secret, createMolecule's wallets and OTS version, queryWallets' token filter,
 *        decryptMyMessage, the validator key in an authorization response and QueryBalance's
 *        response. Driven against the loopback stub validator; no network. `leaks` / LSan runs of
 *        this binary also cover the per-request header list.
 */
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "crypto.h"
#include "http/GraphQLClient.h"
#include "loopback_validator.h"
#include "query/QueryBalance.h"
#include "response/Response.h"
#include "utility.h"

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

}  // namespace

int main() {
    std::cout << "Client operations (loopback stub)" << std::endl;
    passphraseSecret();
    createMolecule();
    queryWalletsFiltersToken();
    decryptMyMessage();
    responses();

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
