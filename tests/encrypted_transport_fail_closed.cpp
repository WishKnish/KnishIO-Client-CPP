/**
 * @file encrypted_transport_fail_closed.cpp
 * @brief An encryption-enabled client must fail CLOSED when the ML-KEM transport keys are
 *        missing, instead of silently sending the operation in plaintext.
 *
 * `executeInternal` used to gate the CipherHash envelope on
 * `cipherEnabled && cipherWallet && serverPubKey.has_value() && shouldEncryptRequest(request)`
 * and, when that was false, fell through to `postData = request.toJsonString()` — the caller
 * asked for an encrypted transport and silently got none. PHP (Libraries/Cipher.php) and Kotlin
 * (httpClient/HttpClient.kt) already threw `Authorized wallet missing.` /
 * `Server public key missing.` here; this pins the same behaviour for C++.
 *
 * The bypass set must keep working: the auth bootstrap (`__schema`, `ContinuId`, `AccessToken`,
 * U-isotope `ProposeMolecule`) cannot be encrypted, because the validator's public key is what it
 * is fetching. A bypassed operation must therefore still be attempted on an encryption-enabled
 * client with no keys.
 *
 * No validator is needed: the URI is a closed loopback port, so a request that IS attempted comes
 * back as a CURL transport error rather than an encryption error.
 */
#include <iostream>
#include <memory>
#include <string>

#include "Wallet.h"

#include "http/GraphQLClient.h"

using knishio::http::EncryptedTransportException;
using knishio::http::GraphQLClient;

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

// Closed loopback port: a request that is actually attempted fails fast with a CURL error.
const std::string kUri = "http://127.0.0.1:1/graphql";

GraphQLClient::Request balanceRequest() {
    GraphQLClient::Request request;
    request.query = "query B { Balance(token: \"USER\") { address } }";
    return request;
}

}  // namespace

int main() {
    std::cout << "Encrypted transport fail-closed (PQ-transport Phase E)\n";

    // (1) Encryption on, no cipher context at all → the request must never leave.
    {
        GraphQLClient client(kUri, 2000, 0);
        client.setEncryption(true);
        std::string message;
        bool threw = false;
        try {
            auto response = client.execute(balanceRequest()).get();
            message = response.error.value_or("(no error, request was sent in plaintext)");
        } catch (const EncryptedTransportException& e) {
            threw = true;
            message = e.what();
        } catch (const std::exception& e) {
            message = std::string("wrong exception type: ") + e.what();
        }
        check(threw && message.find("Authorized wallet missing.") != std::string::npos,
              "a normal operation with no transport keys fails closed", message);
    }

    // (2) A validator public key without a wallet is still unusable → still fails closed.
    {
        GraphQLClient client(kUri, 2000, 0);
        client.setEncryption(true);
        client.setCipherContext(nullptr, "ignored-public-key");
        std::string message;
        bool threw = false;
        try {
            auto response = client.execute(balanceRequest()).get();
            message = response.error.value_or("(no error, request was sent in plaintext)");
        } catch (const EncryptedTransportException& e) {
            threw = true;
            message = e.what();
        } catch (const std::exception& e) {
            message = std::string("wrong exception type: ") + e.what();
        }
        check(threw && message.find("Authorized wallet missing.") != std::string::npos,
              "a pubkey without a wallet fails closed", message);
    }

    // (3) The auth bootstrap must still go out: a bypassed operation is attempted in plaintext,
    //     so what comes back is a transport error, not an encryption error.
    {
        GraphQLClient client(kUri, 2000, 0);
        client.setEncryption(true);
        GraphQLClient::Request request;
        request.query = "query { __schema { types { name } } }";
        std::string message;
        bool threw = false;
        try {
            auto response = client.execute(request).get();
            message = response.error.value_or("(no error)");
        } catch (const std::exception& e) {
            threw = true;
            message = std::string("threw: ") + e.what();
        }
        check(!threw && message.find("CURL error") != std::string::npos,
              "a bypassed operation is still attempted in plaintext", message);
    }

    // (4) An empty advertised key is not a key. This is also the only way the "Server public key
    //     missing." branch is reachable through the public setCipherContext, which always
    //     populates the optional.
    {
        auto wallet = std::make_shared<KnishIO::Wallet>(std::string(2048, 'a'), "AUTH");
        GraphQLClient client(kUri, 2000, 0);
        client.setEncryption(true);
        client.setCipherContext(wallet, "");
        std::string message;
        bool threw = false;
        try {
            auto response = client.execute(balanceRequest()).get();
            message = response.error.value_or("(no error, request was sent in plaintext)");
        } catch (const EncryptedTransportException& e) {
            threw = true;
            message = e.what();
        } catch (const std::exception& e) {
            message = std::string("wrong exception type: ") + e.what();
        }
        check(threw && message.find("Server public key missing.") != std::string::npos,
              "an empty validator key fails closed as missing", message);
    }

    std::cout << (failures == 0 ? "\nAll checks passed\n" : "\nFailures: " + std::to_string(failures) + "\n");
    return failures == 0 ? 0 : 1;
}
