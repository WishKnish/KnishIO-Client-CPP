// Live ML-KEM768 CipherHash encrypted-transport round-trip against a running validator
// (PQ-transport Phase E, cycle 168 — C++).
//
// End-to-end: the client authenticates (conveying its AUTH source wallet's ML-KEM public key via a
// signed walletPubkey U-atom meta), then issues an encrypted queryBalance — the validator
// ML-KEM-decrypts the request, executes it, and encrypts the response back to the client's ML-KEM
// pubkey, which the client decrypts. The transport must be TRANSPARENT, so we assert the encrypted
// result's DATA equals a plaintext baseline (not merely a non-error response).
//
// Gated on CIPHERHASH_TEST_URL (skips cleanly when unset → CI-safe). Run live:
//   CIPHERHASH_TEST_URL=http://localhost:8081/graphql ./build/tests/cipherhash_live_test
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

#include "KnishIOClient.h"
#include "response/Response.h"

int main() {
    const char* envUrl = std::getenv("CIPHERHASH_TEST_URL");
    if (envUrl == nullptr || std::string(envUrl).empty()) {
        std::cout << "SKIP: CIPHERHASH_TEST_URL not set — skipping live CipherHash test\n";
        return 0;
    }
    const std::string url(envUrl);

    try {
        const std::string secret = knishio::KnishIOClient::generateSecret(2048);

        auto client = knishio::KnishIOClient::Builder()
            .uris({url})
            .timeout(std::chrono::milliseconds(15000))
            .build();

        // ONE authenticated session (encrypt=true → conveys the AUTH wallet's ML-KEM pubkey as a
        // signed walletPubkey U-atom meta, so the validator can encrypt responses back to it). We
        // vary ONLY the transport on this SAME session — the queried balance wallet stays fixed.
        // (A fresh second auth would rotate the USER remainder via ContinuID → a different address/
        // position: correct protocol behaviour, NOT a transport bug.)
        client->requestAuthToken(secret, std::optional<std::string>("public"), true).get();

        // Encrypted round-trip: the validator ML-KEM-decrypts the request, executes it, and encrypts
        // the response back to the client's ML-KEM pubkey; the client decrypts it.
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
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: exception: " << e.what() << "\n";
        return 1;
    }
}
