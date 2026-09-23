// Live ML-KEM CipherHash encrypted-transport round-trip against a running validator
// (PQ-transport Phase E, cycle 168 — C++).
//
// End-to-end: the client authenticates (conveying its AUTH source wallet's ML-KEM public key via a
// signed walletPubkey U-atom meta), then issues an encrypted queryBalance — the validator
// ML-KEM-decrypts the request, executes it, and encrypts the response back to the client's ML-KEM
// pubkey, which the client decrypts. The transport must be TRANSPARENT, so we assert the encrypted
// result's DATA equals a plaintext baseline (not merely a non-error response).
//
// Gated on CIPHERHASH_TEST_URL: unset, it exits 77, which ctest reports as Skipped (SKIP_RETURN_CODE in
// tests/CMakeLists.txt) rather than Passed. Run live:
//   CIPHERHASH_TEST_URL=http://localhost:8081/graphql ./build/tests/cipherhash_live_test
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

#include "KnishIOClient.h"
#include "http/GraphQLClient.h"
#include "response/Response.h"

int main() {
    const char* envUrl = std::getenv("CIPHERHASH_TEST_URL");
    if (envUrl == nullptr || std::string(envUrl).empty()) {
        std::cout << "SKIP: CIPHERHASH_TEST_URL not set — skipping live CipherHash test\n";
        return 77;  // ctest SKIP_RETURN_CODE: reported as Skipped, never as Passed
    }
    const std::string url(envUrl);

    try {
        const std::string secret = knishio::KnishIOClient::generateSecret(2048);

        const char* param_env = std::getenv("CIPHERHASH_MLKEM_PARAMETER_SET");
        int param = (param_env && std::string(param_env) == "768") ? 768 : 1024;

        auto client = knishio::KnishIOClient::Builder()
            .uris({url})
            .timeout(std::chrono::milliseconds(15000))
            .mlKemParameterSet(param)
            .build();

        // ONE session, transport toggled on it — the queried balance wallet stays fixed. (A fresh
        // second auth would rotate the USER remainder via ContinuID → a different address/position:
        // correct protocol behaviour, NOT a transport bug.)
        //
        // The session authenticates PLAINTEXT on purpose. The AUTH wallet's ML-KEM pubkey is
        // conveyed as a signed walletPubkey U-atom meta regardless of `encrypt`, and the cipher
        // context is plumbed either way (KnishIOClient.cpp:925-929), so a plaintext-authenticated
        // session still speaks the encrypted transport. Authenticating with encrypt=true instead
        // would make the plaintext baseline leg below a silent downgrade, which the validator
        // rejects when ENFORCE_ENCRYPTED_TRANSPORT is at its secure default.
        client->requestAuthToken(secret, std::optional<std::string>("public"), false).get();

        // Encrypted round-trip: the validator ML-KEM-decrypts the request, executes it, and encrypts
        // the response back to the client's ML-KEM pubkey; the client decrypts it.
        client->switchEncryption(true);
        auto encResp = client->queryBalance("USER").get();

        // Plaintext baseline of the SAME wallet on the SAME authed session — only transport differs.
        client->switchEncryption(false);
        auto plainResp = client->queryBalance("USER").get();

        if (!encResp || !plainResp) {
            std::cerr << "FAIL: queryBalance returned a null response\n";
            return 1;
        }

        auto enc = encResp->getBalance();
        auto plain = plainResp->getBalance();

        // The PQ transport must be transparent: not just a non-error response, but the SAME data.
        // A missing encrypted balance would mean the transport silently dropped the data.
        if (!enc.has_value()) {
            std::cerr << "FAIL: encrypted queryBalance returned no balance (transport must deliver data)\n";
            return 1;
        }
        if (!plain.has_value()) {
            std::cerr << "FAIL: plaintext queryBalance returned no balance\n";
            return 1;
        }

        // Same authed session → identical balance wallet → its deterministic identity fields match.
        const bool ok =
            enc->address == plain->address &&
            enc->position == plain->position &&
            enc->bundleHash == plain->bundleHash &&
            enc->tokenSlug == plain->tokenSlug &&
            enc->amount == plain->amount;

        if (!ok) {
            std::cerr << "FAIL: encrypted balance != plaintext balance\n"
                      << "  enc:   address=" << enc->address << " position=" << enc->position << "\n"
                      << "  plain: address=" << plain->address << " position=" << plain->position << "\n";
            return 1;
        }

        std::cout << "PASS: encrypted queryBalance round-trips (matches plaintext); address="
                  << enc->address << "\n";

        // Scenario 2 — live coverage of the enforcement path: extract_encrypt_flag →
        // auth_tokens.encrypted → requires_encrypted_transport. A session that authenticated with
        // encrypt=true must NOT be able to fall back to plaintext. This also proves this SDK's
        // signed `encrypt` meta literal is the one the validator honours.
        const std::string secret2 = knishio::KnishIOClient::generateSecret(2048);
        auto client2 = knishio::KnishIOClient::Builder()
            .uris({url})
            .timeout(std::chrono::milliseconds(15000))
            .mlKemParameterSet(param)
            .build();
        auto auth = client2->requestAuthToken(secret2, std::optional<std::string>("public"), true).get();
        if (!auth || auth->getAuthToken().empty()) {
            std::cerr << "FAIL: encrypt=true authentication returned no token\n";
            return 1;
        }

        // The encrypted transport still works for this session.
        auto encOnly = client2->queryBalance("USER").get();
        if (!encOnly || !encOnly->getBalance().has_value()) {
            std::cerr << "FAIL: encrypt=true session could not complete an encrypted query\n";
            return 1;
        }

        // Dropping to plaintext must be refused. Read the refusal from the RAW GraphQL response:
        // queryBalance routes through resolveTokenWallet, which reports any GraphQL error as
        // "not found" and so cannot distinguish a refusal from an absent balance.
        knishio::http::GraphQLClient raw(url, 15000, 0);   // cipherEnabled defaults false → plaintext
        raw.setAuthToken(auth->getAuthToken());
        knishio::http::GraphQLClient::Request plainReq;
        plainReq.query = "query { Balance(token: \"USER\") { address } }";
        auto body = raw.execute(plainReq).get().toJson();
        const bool refused =
            body.contains("errors") && body["errors"].is_array() && !body["errors"].empty()
            && body["errors"][0].contains("message")
            && body["errors"][0]["message"].get<std::string>()
                   .find("CipherHash encrypted transport") != std::string::npos;
        if (!refused) {
            std::cerr << "FAIL: plaintext request from an encrypt=true session was not refused\n"
                      << "  body=" << body.dump() << "\n";
            return 1;
        }

        std::cout << "PASS: an encrypt=true session is refused when it drops to plaintext\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: exception: " << e.what() << "\n";
        return 1;
    }
}
