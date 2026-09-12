#include "storage/SecretEnvelope.h"
#include <iostream>
#include <string>

using namespace knishio::storage;

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: secret_storage_cli <seal|open> [args...]\n";
        return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "seal" || cmd == "seal-recovery") {
        if (argc < 5) {
            std::cerr << "Usage: secret_storage_cli seal <passphrase> <secret> <bundleHash> [label]\n";
            return 1;
        }
        std::string passphrase = argv[2];
        std::string secret = argv[3];
        std::string bundleHash = argv[4];
        std::optional<std::string> label = std::nullopt;
        if (argc >= 6 && std::string(argv[5]).length() > 0) {
            label = argv[5];
        }
        SecretStorageMetadata meta{
            .bundleHash = bundleHash,
            .label = label,
            .createdAt = 1700000000000,
            .hardwareBacked = false,
            .providerType = "aes-gcm",
        };
        auto payload = seal(secret, passphrase, meta);
        std::cout << payload.toJson().dump() << "\n";
        return 0;
    } else if (cmd == "open") {
        if (argc < 4) {
            std::cerr << "Usage: secret_storage_cli open <passphrase> <payloadJson>\n";
            return 1;
        }
        std::string passphrase = argv[2];
        std::string payloadJson = argv[3];
        auto payload = EncryptedSecretPayload::fromString(payloadJson);
        std::string plain = open(payload, passphrase);
        std::cout << plain << "\n";
        return 0;
    }
    std::cerr << "Unknown command: " << cmd << "\n";
    return 1;
}
