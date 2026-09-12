#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "third_party/nlohmann/json.hpp"

namespace knishio {
namespace storage {

constexpr uint32_t DEFAULT_ITERATIONS = 100000;
constexpr size_t SALT_LENGTH = 16;
constexpr size_t IV_LENGTH = 12;
constexpr size_t TAG_LENGTH = 16;
constexpr size_t KEY_LENGTH = 32;

/**
 * Metadata associated with an encrypted secret in storage.
 *
 * Wire format is camelCase. This is a cross-SDK contract.
 */
struct SecretStorageMetadata {
    std::string bundleHash;
    std::optional<std::string> label;
    int64_t createdAt = 0;
    bool hardwareBacked = false;
    std::string providerType;

    nlohmann::json toJson() const;
    static SecretStorageMetadata fromJson(const nlohmann::json& j);

    bool operator==(const SecretStorageMetadata& other) const = default;
};

/**
 * Versioned envelope encryption payload
 */
struct EncryptedSecretPayload {
    uint32_t version = 1;
    std::string ciphertext; // Base64 ciphertext + tag
    std::string iv;         // Base64 12-byte IV
    std::string salt;       // Base64 16-byte salt
    std::string algorithm = "AES-GCM";
    uint32_t iterations = DEFAULT_ITERATIONS;
    SecretStorageMetadata metadata;

    nlohmann::json toJson() const;
    static EncryptedSecretPayload fromJson(const nlohmann::json& j);
    static EncryptedSecretPayload fromString(const std::string& jsonStr);
    std::string toString(int indent = -1) const;
};

/**
 * Derive 32-byte AES key from passphrase and salt using PBKDF2-HMAC-SHA256
 */
std::vector<uint8_t> deriveKey(const std::string& passphrase,
                               const std::vector<uint8_t>& salt,
                               uint32_t iterations = DEFAULT_ITERATIONS);

/**
 * Seal a secret into an EncryptedSecretPayload envelope
 */
EncryptedSecretPayload seal(const std::string& secret,
                            const std::string& passphrase,
                            const SecretStorageMetadata& metadata);

/**
 * Open an EncryptedSecretPayload envelope with a passphrase, returning plaintext
 */
std::string open(const EncryptedSecretPayload& payload,
                 const std::string& passphrase);

} // namespace storage
} // namespace knishio

namespace KnishIO {
namespace storage {
    using knishio::storage::SecretStorageMetadata;
    using knishio::storage::EncryptedSecretPayload;
    using knishio::storage::deriveKey;
    using knishio::storage::seal;
    using knishio::storage::open;
} // namespace storage
} // namespace KnishIO
