#include "storage/SecretEnvelope.h"
#include "storage/SecretStorageException.h"
#include "storage/SecureMemory.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <sstream>

namespace knishio {
namespace storage {

using json = nlohmann::json;

namespace {

constexpr std::string_view BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string encodeBase64(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t val = 0;
        uint32_t count = 0;

        for (size_t j = 0; j < 3 && i + j < data.size(); ++j) {
            val = (val << 8u) | static_cast<uint32_t>(data[i + j]);
            ++count;
        }

        val <<= (3u - count) * 8u;

        for (size_t j = 0; j < 4; ++j) {
            if (j <= count) {
                uint32_t shift = 18u - static_cast<uint32_t>(j) * 6u;
                result += BASE64_CHARS[static_cast<size_t>((val >> shift) & 0x3Fu)];
            } else {
                result += '=';
            }
        }
    }

    return result;
}

std::vector<uint8_t> decodeBase64(const std::string& str) {
    if (str.empty()) {
        return {};
    }

    // Filter out whitespace
    std::string clean;
    clean.reserve(str.size());
    for (char c : str) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            clean += c;
        }
    }

    if (clean.size() % 4 != 0) {
        throw SecretStorageException::decryptionFailed("Invalid Base64 length");
    }

    std::vector<int> table(256, -1);
    for (size_t i = 0; i < BASE64_CHARS.size(); ++i) {
        table[static_cast<unsigned char>(BASE64_CHARS[i])] = static_cast<int>(i);
    }

    std::vector<uint8_t> result;
    result.reserve((clean.size() / 4) * 3);

    for (size_t i = 0; i < clean.size(); i += 4) {
        uint32_t val = 0;
        uint32_t count = 0;

        for (size_t j = 0; j < 4; ++j) {
            char c = clean[i + j];
            if (c != '=') {
                int idx = table[static_cast<unsigned char>(c)];
                if (idx == -1) {
                    throw SecretStorageException::decryptionFailed("Invalid Base64 character: " + std::string(1, c));
                }
                val = (val << 6u) | static_cast<uint32_t>(idx);
                ++count;
            }
        }

        val <<= (4u - count) * 6u;

        for (size_t j = 0; j + 1 < count; ++j) {
            uint32_t shift = 16u - static_cast<uint32_t>(j) * 8u;
            result.push_back(static_cast<uint8_t>((val >> shift) & 0xFFu));
        }
    }
    return result;
}

} // anonymous namespace

// ============================================================================
// SecretStorageMetadata
// ============================================================================

json SecretStorageMetadata::toJson() const {
    json j;
    j["bundleHash"] = bundleHash;
    j["createdAt"] = createdAt;
    j["hardwareBacked"] = hardwareBacked;
    j["providerType"] = providerType;

    if (label.has_value() && !label.value().empty()) {
        j["label"] = label.value();
    }

    return j;
}

SecretStorageMetadata SecretStorageMetadata::fromJson(const json& j) {
    if (!j.is_object()) {
        throw SecretStorageException("Invalid metadata: expected JSON object");
    }

    SecretStorageMetadata meta;

    // bundleHash (required, tolerate bundle_hash)
    const std::string bhKey = j.contains("bundleHash") ? "bundleHash" : "bundle_hash";
    if (j.contains(bhKey)) {
        meta.bundleHash = j[bhKey].get<std::string>();
    } else {
        throw SecretStorageException("Metadata missing required field 'bundleHash'");
    }

    // createdAt (required, tolerate created_at)
    const std::string caKey = j.contains("createdAt") ? "createdAt" : "created_at";
    if (j.contains(caKey)) {
        meta.createdAt = j[caKey].get<int64_t>();
    } else {
        throw SecretStorageException("Metadata missing required field 'createdAt'");
    }

    // hardwareBacked (required, tolerate hardware_backed)
    const std::string hbKey = j.contains("hardwareBacked") ? "hardwareBacked" : "hardware_backed";
    if (j.contains(hbKey)) {
        meta.hardwareBacked = j[hbKey].get<bool>();
    } else {
        meta.hardwareBacked = false;
    }

    // providerType (required, tolerate provider_type)
    const std::string ptKey = j.contains("providerType") ? "providerType" : "provider_type";
    if (j.contains(ptKey)) {
        meta.providerType = j[ptKey].get<std::string>();
    } else {
        throw SecretStorageException("Metadata missing required field 'providerType'");
    }
    // label (optional, omit when null or absent)
    if (j.contains("label") && !j["label"].is_null()) {
        meta.label = j["label"].get<std::string>();
    }

    return meta;
}

// ============================================================================
// EncryptedSecretPayload
// ============================================================================

json EncryptedSecretPayload::toJson() const {
    json j;
    j["version"] = version;
    j["ciphertext"] = ciphertext;
    j["iv"] = iv;
    j["salt"] = salt;
    j["algorithm"] = algorithm;
    j["iterations"] = iterations;
    j["metadata"] = metadata.toJson();
    return j;
}

EncryptedSecretPayload EncryptedSecretPayload::fromJson(const json& j) {
    if (!j.is_object()) {
        throw SecretStorageException("Invalid payload: expected JSON object");
    }

    EncryptedSecretPayload payload;

    if (!j.contains("version") || !j.contains("ciphertext") || !j.contains("iv") ||
        !j.contains("salt") || !j.contains("metadata")) {
        throw SecretStorageException("Payload missing required fields");
    }

    payload.version = j["version"].get<uint32_t>();
    payload.ciphertext = j["ciphertext"].get<std::string>();
    payload.iv = j["iv"].get<std::string>();
    payload.salt = j["salt"].get<std::string>();

    if (j.contains("algorithm")) {
        payload.algorithm = j["algorithm"].get<std::string>();
    }
    if (j.contains("iterations")) {
        payload.iterations = j["iterations"].get<uint32_t>();
    }

    payload.metadata = SecretStorageMetadata::fromJson(j["metadata"]);
    return payload;
}

EncryptedSecretPayload EncryptedSecretPayload::fromString(const std::string& jsonStr) {
    try {
        json j = json::parse(jsonStr);
        return fromJson(j);
    } catch (const SecretStorageException&) {
        throw;
    } catch (const std::exception& e) {
        throw SecretStorageException::decryptionFailed("Corrupted payload format: " + std::string(e.what()));
    }
}

std::string EncryptedSecretPayload::toString(int indent) const {
    return toJson().dump(indent);
}

// ============================================================================
// Cryptographic Operations
// ============================================================================

std::vector<uint8_t> deriveKey(const std::string& passphrase,
                               const std::vector<uint8_t>& salt,
                               uint32_t iterations) {
    std::vector<uint8_t> key(KEY_LENGTH);
    if (PKCS5_PBKDF2_HMAC(
            passphrase.c_str(), static_cast<int>(passphrase.size()),
            salt.data(), static_cast<int>(salt.size()),
            static_cast<int>(iterations),
            EVP_sha256(),
            static_cast<int>(KEY_LENGTH),
            key.data()) != 1) {
        zeroizeBytes(key);
        throw SecretStorageException("PBKDF2-HMAC-SHA256 key derivation failed");
    }
    return key;
}

EncryptedSecretPayload seal(const std::string& secret,
                            const std::string& passphrase,
                            const SecretStorageMetadata& metadata) {
    std::vector<uint8_t> salt(SALT_LENGTH);
    if (RAND_bytes(salt.data(), static_cast<int>(SALT_LENGTH)) != 1) {
        throw SecretStorageException("Failed to generate random salt");
    }

    std::vector<uint8_t> iv(IV_LENGTH);
    if (RAND_bytes(iv.data(), static_cast<int>(IV_LENGTH)) != 1) {
        throw SecretStorageException("Failed to generate random IV");
    }

    std::vector<uint8_t> key = deriveKey(passphrase, salt, DEFAULT_ITERATIONS);

    // Prepare buffer: ciphertext + 16-byte tag
    std::vector<uint8_t> output(secret.size() + TAG_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        zeroizeBytes(key);
        throw SecretStorageException("Failed to allocate cipher context");
    }

    int len = 0;
    int ciphertext_len = 0;
    bool ok = (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LENGTH), nullptr) == 1) &&
             (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1) &&
             (EVP_EncryptUpdate(ctx, output.data(), &len,
                                reinterpret_cast<const uint8_t*>(secret.data()),
                                static_cast<int>(secret.size())) == 1);
    if (ok) {
        ciphertext_len = len;
        ok = (EVP_EncryptFinal_ex(ctx, output.data() + ciphertext_len, &len) == 1);
        ciphertext_len += len;
    }
    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LENGTH),
                                  output.data() + ciphertext_len) == 1);
        ciphertext_len += TAG_LENGTH;
    }
    EVP_CIPHER_CTX_free(ctx);
    zeroizeBytes(key);

    if (!ok) {
        zeroizeBytes(output);
        throw SecretStorageException("AES-256-GCM encryption failed");
    }

    output.resize(static_cast<size_t>(ciphertext_len));

    EncryptedSecretPayload payload;
    payload.version = 1;
    payload.ciphertext = encodeBase64(output);
    payload.iv = encodeBase64(iv);
    payload.salt = encodeBase64(salt);
    payload.algorithm = "AES-GCM";
    payload.iterations = DEFAULT_ITERATIONS;
    payload.metadata = metadata;

    zeroizeBytes(output);
    return payload;
}

std::string open(const EncryptedSecretPayload& payload,
                 const std::string& passphrase) {
    std::vector<uint8_t> salt;
    try {
        salt = decodeBase64(payload.salt);
    } catch (const std::exception& e) {
        throw SecretStorageException::decryptionFailed("Invalid salt Base64: " + std::string(e.what()));
    }

    std::vector<uint8_t> iv;
    try {
        iv = decodeBase64(payload.iv);
    } catch (const std::exception& e) {
        throw SecretStorageException::decryptionFailed("Invalid IV Base64: " + std::string(e.what()));
    }

    if (iv.size() != IV_LENGTH) {
        throw SecretStorageException::decryptionFailed("Invalid IV length: expected 12 bytes");
    }

    std::vector<uint8_t> ciphertextWithTag;
    try {
        ciphertextWithTag = decodeBase64(payload.ciphertext);
    } catch (const std::exception& e) {
        throw SecretStorageException::decryptionFailed("Invalid ciphertext Base64: " + std::string(e.what()));
    }

    if (ciphertextWithTag.size() < TAG_LENGTH) {
        throw SecretStorageException::decryptionFailed("Ciphertext too short for authentication tag");
    }

    const size_t ciphertext_len = ciphertextWithTag.size() - TAG_LENGTH;
    const uint8_t* tag = ciphertextWithTag.data() + ciphertext_len;

    std::vector<uint8_t> key = deriveKey(passphrase, salt, payload.iterations);

    std::vector<uint8_t> plaintext(ciphertext_len > 0 ? ciphertext_len : 1);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        zeroizeBytes(key);
        throw SecretStorageException::decryptionFailed("Failed to allocate cipher context");
    }

    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    bool ok = (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1) &&
             (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_LENGTH), nullptr) == 1) &&
             (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) == 1);

    if (ok && ciphertext_len > 0) {
        ok = (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                ciphertextWithTag.data(), static_cast<int>(ciphertext_len)) == 1);
        plaintext_len = len;
    }

    if (ok) {
        ok = (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_LENGTH),
                                  const_cast<uint8_t*>(tag)) == 1);
    }

    if (ok) {
        ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
    }

    EVP_CIPHER_CTX_free(ctx);
    zeroizeBytes(key);

    if (!ok || ret <= 0) {
        zeroizeBytes(plaintext);
        throw SecretStorageException::decryptionFailed("Authentication tag mismatch or decryption failure");
    }

    plaintext.resize(static_cast<size_t>(plaintext_len) + static_cast<size_t>(len));
    std::string result(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    zeroizeBytes(plaintext);
    return result;
}

} // namespace storage
} // namespace knishio
