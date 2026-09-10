/**
 * @file mlkem_encaps_entropy.cpp
 * @brief Prove-the-gate harness for ML-KEM encapsulation randomness (mirror of the C harness).
 *
 * Builds a FIXED ML-KEM keypair at the wallet's default parameter set from a constant wallet
 * secret, performs ONE encapsulation to that key via Wallet::encryptMessageML, and prints the
 * KEM ciphertext (the map's "cipherText" field) to stdout.
 *
 * Rationale: ML-KEM derandomizes K-PKE (r = G(m || H(ek))), so the ONLY entropy in the KEM
 * ciphertext is the 32-byte message m. A CSPRNG-backed build prints a DIFFERENT cipherText on
 * every process launch; a constant-seed RNG (the mlkem-native test stub) prints the SAME one.
 * (We print cipherText, NOT encryptedMessage: the latter also varies via the random AES-GCM IV,
 * so only cipherText isolates the encapsulation randomness.)
 *
 * run_encaps_entropy_twice.cmake runs this binary twice as separate processes and asserts the
 * two outputs differ.
 */
#include <cstdio>
#include <string>
#include <map>

#include "KnishIOClient.h"
#include "Wallet.h"
#include "utility.h"

int main() {
    // Fixed secret -> deterministic ML-KEM keypair -> fixed public key.
    const std::string secret = knishio::KnishIOClient::generateSecret("MLKEM-ENTROPY-GATE-SEED");
    KnishIO::Wallet wallet(
        secret, "ENCRYPT",
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");

    if (wallet.mlkem_public_key.empty()) {
        std::fprintf(stderr, "mlkem_encaps_entropy: no ML-KEM public key\n");
        return 2;
    }

    const std::string pubkey_b64 = toBase64(wallet.mlkem_public_key);
    std::map<std::string, std::string> envelope =
        wallet.encryptMessageML("entropy-probe", pubkey_b64);

    const std::string& cipher_text = envelope["cipherText"];
    if (cipher_text.empty()) {
        std::fprintf(stderr, "mlkem_encaps_entropy: empty cipherText\n");
        return 2;
    }

    std::printf("%s\n", cipher_text.c_str());
    return 0;
}
