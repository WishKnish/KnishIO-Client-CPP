/**
 * @file encrypted_reply_rule.cpp
 * @brief The reply to a request this client wrapped in the CipherHash envelope must fail CLOSED
 *        unless it is a decryptable envelope or an errors-only reply.
 *
 * `executeInternal` used to try the envelope and, when the reply was anything else (plaintext
 * `data`, an envelope that did not decrypt, a body that was not JSON), silently returned it as if
 * the validator had sent it — so whoever sits between the client and the validator could answer an
 * encrypted request in plaintext. PHP (Libraries/Cipher.php) and the C SDK (client.c) already
 * refused those replies; this pins the same rule for C++:
 *   - `data.CipherHash.hash` is a string → it must decrypt for this wallet;
 *   - no envelope and `data` absent, null or `{}` → passed through, so the validator's `errors`
 *     stay visible;
 *   - no envelope and any other `data` → refused;
 *   - a 2xx body that is not JSON → refused.
 * Each refusal is an EncryptedTransportException, which the retry loop rethrows at once.
 *
 * Driven against the loopback stub validator, which answers every request with a fixed body.
 */
#include <iostream>
#include <memory>
#include <string>

#include "Wallet.h"
#include "utility.h"

#include "http/GraphQLClient.h"
#include "loopback_validator.h"

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

GraphQLClient::Request balanceRequest() {
    GraphQLClient::Request request;
    request.query = "query B { Balance(token: \"USER\") { address } }";
    return request;
}

struct Outcome {
    bool threwTransport = false;   // EncryptedTransportException
    std::string message;           // its what(), or a description of what came back instead
    GraphQLClient::Response response;
};

// One keyed (encryption-enabled) Balance request against a stub that answers with `reply`.
Outcome send(const std::shared_ptr<KnishIO::Wallet>& wallet, const std::string& reply) {
    knishio_test::StubValidator stub;
    stub.setRawReply(reply);
    GraphQLClient client(stub.uri(), 5000, 0);
    client.setEncryption(true);
    client.setCipherContext(wallet, toBase64(wallet->mlkem_public_key));
    Outcome outcome;
    try {
        outcome.response = client.execute(balanceRequest()).get();
        outcome.message = "(no exception; body: " + outcome.response.body + ")";
    } catch (const EncryptedTransportException& e) {
        outcome.threwTransport = true;
        outcome.message = e.what();
    } catch (const std::exception& e) {
        outcome.message = std::string("wrong exception type: ") + e.what();
    }
    const auto sent = stub.requests("CipherHash");
    if (sent.empty()) {
        outcome.threwTransport = false;
        outcome.message = "the request was not wrapped in the CipherHash envelope: " + outcome.message;
    }
    return outcome;
}

}  // namespace

int main() {
    std::cout << "Encrypted reply rule (PQ-transport Phase E)\n";

    auto wallet = std::make_shared<KnishIO::Wallet>(std::string(2048, 'a'), "AUTH");

    // (1) Plaintext `data` answering an encrypted request is refused.
    {
        const auto outcome = send(wallet, R"({"data":{"Balance":{"address":"x"}}})");
        check(outcome.threwTransport
                  && outcome.message.find("CipherHash: plaintext reply to an encrypted request") != std::string::npos,
              "a plaintext data reply is rejected", outcome.message);
    }

    // (2) An errors-only reply (data: null) passes through with the validator's message intact.
    {
        const std::string validatorMessage = "CipherHash: no envelope addressed to the validator";
        const auto outcome =
            send(wallet, R"({"data":null,"errors":[{"message":")" + validatorMessage + R"("}]})");
        const bool surfaced = outcome.response.error.has_value()
            && outcome.response.error->find(validatorMessage) != std::string::npos;
        check(!outcome.threwTransport && outcome.message.rfind("(no exception", 0) == 0 && surfaced,
              "an errors-only reply passes through", outcome.message);
    }

    // (3) An envelope with no entry for this wallet does not decrypt → refused.
    {
        const auto outcome = send(wallet, R"({"data":{"CipherHash":{"hash":"{}"}}})");
        check(outcome.threwTransport
                  && outcome.message.find("CipherHash: reply could not be decrypted") != std::string::npos,
              "an undecryptable envelope is rejected", outcome.message);
    }

    // (4) A 200 reply that is not JSON is refused.
    {
        const auto outcome = send(wallet, "<html>not json</html>");
        check(outcome.threwTransport
                  && outcome.message.find("CipherHash: reply is not valid JSON") != std::string::npos,
              "a non-JSON 200 reply is rejected", outcome.message);
    }

    // (5) A genuine envelope addressed to this wallet is still unwrapped (the rule rejects no
    //     legitimate reply).
    {
        const std::string inner = R"({"data":{"Balance":null}})";
        const std::string hash = wallet->encryptStringML(inner, toBase64(wallet->mlkem_public_key));
        const auto outcome = send(wallet, nlohmann::json{{"data", {{"CipherHash", {{"hash", hash}}}}}}.dump());
        check(!outcome.threwTransport && outcome.response.body == nlohmann::json(inner).dump(),
              "a decryptable envelope is unwrapped", outcome.message);
    }

    std::cout << (failures == 0 ? "\nAll checks passed\n" : "\nFailures: " + std::to_string(failures) + "\n");
    return failures == 0 ? 0 : 1;
}
