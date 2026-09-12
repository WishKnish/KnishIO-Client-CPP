#include "storage/SecretStorageProvider.h"
#include "storage/SecretStorageException.h"
#include "storage/SecureMemory.h"
#include <chrono>

namespace knishio {
namespace storage {

// ============================================================================
// SecretStorageProvider Base
// ============================================================================

void SecretStorageProvider::withSecret(const std::string& bundleHash,
                                       const StorageOptions& options,
                                       const std::function<void(const std::string&)>& callback) {
    auto secret = retrieveSecret(bundleHash, options);
    if (!secret.has_value()) {
        throw SecretStorageException::notFound(bundleHash);
    }
    withSecureString(secret.value(), callback);
}

// ============================================================================
// AesGcmSecretStorageProvider
// ============================================================================

AesGcmSecretStorageProvider::AesGcmSecretStorageProvider(std::shared_ptr<StorageBackend> backend,
                                                         std::optional<std::string> defaultPassphrase)
    : backend_(backend ? std::move(backend) : std::make_shared<MemoryStorageBackend>()),
      defaultPassphrase_(std::move(defaultPassphrase)) {}

void AesGcmSecretStorageProvider::storeSecret(const std::string& bundleHash,
                                             const std::string& secret,
                                             const StorageOptions& options) {
    if (bundleHash.empty()) {
        throw SecretStorageException("Bundle hash cannot be empty");
    }
    if (secret.empty()) {
        throw SecretStorageException("Secret cannot be empty");
    }

    std::optional<std::string> passphrase = options.passphrase.has_value()
        ? options.passphrase
        : defaultPassphrase_;

    if (!passphrase.has_value() || passphrase->empty()) {
        throw SecretStorageException("Passphrase required for envelope encryption");
    }

    auto now = std::chrono::system_clock::now();
    int64_t createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    SecretStorageMetadata meta;
    meta.bundleHash = bundleHash;
    meta.label = options.label;
    meta.createdAt = createdAt;
    meta.hardwareBacked = false;
    meta.providerType = "aes-gcm";

    EncryptedSecretPayload payload = seal(secret, *passphrase, meta);
    backend_->setItem(std::string(KEY_PREFIX) + bundleHash, payload.toString());
    if (options.recoveryPassphrase.has_value()) {
        if (options.recoveryPassphrase->empty()) {
            throw SecretStorageException("Recovery passphrase cannot be empty");
        }
        SecretStorageMetadata recoveryMeta;
        recoveryMeta.bundleHash = bundleHash;
        recoveryMeta.label = options.label;
        recoveryMeta.createdAt = createdAt;
        recoveryMeta.hardwareBacked = false;
        recoveryMeta.providerType = "aes-gcm";

        EncryptedSecretPayload recoveryPayload = seal(secret, *options.recoveryPassphrase, recoveryMeta);
        backend_->setItem(std::string(RECOVERY_KEY_PREFIX) + bundleHash, recoveryPayload.toString());
    }
}
std::optional<std::string> AesGcmSecretStorageProvider::retrieveSecret(const std::string& bundleHash,
                                                                      const StorageOptions& options) {
    auto raw = backend_->getItem(std::string(KEY_PREFIX) + bundleHash);
    if (!raw.has_value()) {
        return std::nullopt;
    }

    EncryptedSecretPayload payload = EncryptedSecretPayload::fromString(*raw);

    std::optional<std::string> passphrase = options.passphrase.has_value()
        ? options.passphrase
        : defaultPassphrase_;

    if (!passphrase.has_value() || passphrase->empty()) {
        throw SecretStorageException("Passphrase required for secret decryption");
    }

    return open(payload, *passphrase);
}

bool AesGcmSecretStorageProvider::deleteSecret(const std::string& bundleHash) {
    bool removedPrimary = backend_->removeItem(std::string(KEY_PREFIX) + bundleHash);
    bool removedRecovery = backend_->removeItem(std::string(RECOVERY_KEY_PREFIX) + bundleHash);
    return removedPrimary || removedRecovery;
}

bool AesGcmSecretStorageProvider::hasSecret(const std::string& bundleHash) {
    return backend_->getItem(std::string(KEY_PREFIX) + bundleHash).has_value();
}

std::vector<SecretStorageMetadata> AesGcmSecretStorageProvider::listSecrets() {
    std::vector<SecretStorageMetadata> result;
    const std::string prefix = KEY_PREFIX;
    const std::string recoveryPrefix = RECOVERY_KEY_PREFIX;

    for (const auto& key : backend_->keys()) {
        if (key.rfind(prefix, 0) == 0 && key.rfind(recoveryPrefix, 0) != 0) {
            auto raw = backend_->getItem(key);
            if (raw.has_value()) {
                try {
                    auto payload = EncryptedSecretPayload::fromString(*raw);
                    result.push_back(payload.metadata);
                } catch (...) {
                    // Skip unparseable items
                }
            }
        }
    }

    return result;
}

void AesGcmSecretStorageProvider::recoverSecret(const std::string& bundleHash,
                                                const std::string& recoveryPassphrase,
                                                const StorageOptions& options) {
    if (bundleHash.empty()) {
        throw SecretStorageException("Bundle hash cannot be empty");
    }
    if (recoveryPassphrase.empty()) {
        throw SecretStorageException("Recovery passphrase cannot be empty");
    }

    auto raw = backend_->getItem(std::string(RECOVERY_KEY_PREFIX) + bundleHash);
    if (!raw.has_value()) {
        throw SecretStorageException::notFound(bundleHash);
    }

    EncryptedSecretPayload payload = EncryptedSecretPayload::fromString(*raw);
    std::string secret = open(payload, recoveryPassphrase);

    StorageOptions storeOpts = options;
    if (!storeOpts.passphrase.has_value()) {
        if (defaultPassphrase_.has_value()) {
            storeOpts.passphrase = defaultPassphrase_;
        } else {
            storeOpts.passphrase = recoveryPassphrase;
        }
    }
    storeOpts.recoveryPassphrase = recoveryPassphrase;

    storeSecret(bundleHash, secret, storeOpts);
    zeroizeString(secret);
}

// ============================================================================
// MemorySecretStorageProvider
// ============================================================================

void MemorySecretStorageProvider::storeSecret(const std::string& bundleHash,
                                             const std::string& secret,
                                             const StorageOptions& options) {
    if (bundleHash.empty()) {
        throw SecretStorageException("Bundle hash cannot be empty");
    }
    if (secret.empty()) {
        throw SecretStorageException("Secret cannot be empty");
    }

    auto now = std::chrono::system_clock::now();
    int64_t createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    SecretStorageMetadata meta;
    meta.bundleHash = bundleHash;
    meta.label = options.label;
    meta.createdAt = createdAt;
    meta.hardwareBacked = false;
    meta.providerType = "memory";

    std::lock_guard<std::mutex> lock(mutex_);
    store_[bundleHash] = Entry{secret, meta};

    if (options.recoveryPassphrase.has_value()) {
        if (options.recoveryPassphrase->empty()) {
            throw SecretStorageException("Recovery passphrase cannot be empty");
        }
        SecretStorageMetadata recoveryMeta;
        recoveryMeta.bundleHash = bundleHash;
        recoveryMeta.label = options.label;
        recoveryMeta.createdAt = createdAt;
        recoveryMeta.hardwareBacked = false;
        recoveryMeta.providerType = "aes-gcm";

        EncryptedSecretPayload recoveryPayload = seal(secret, *options.recoveryPassphrase, recoveryMeta);
        recoveryStore_[bundleHash] = recoveryPayload.toString();
    }
}

std::optional<std::string> MemorySecretStorageProvider::retrieveSecret(const std::string& bundleHash,
                                                                      const StorageOptions& /*options*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = store_.find(bundleHash);
    if (it != store_.end()) {
        return it->second.secret;
    }
    return std::nullopt;
}

bool MemorySecretStorageProvider::deleteSecret(const std::string& bundleHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    bool removedRec = recoveryStore_.erase(bundleHash) > 0;
    bool removedPrim = store_.erase(bundleHash) > 0;
    return removedPrim || removedRec;
}

void MemorySecretStorageProvider::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    store_.clear();
    recoveryStore_.clear();
}

bool MemorySecretStorageProvider::hasSecret(const std::string& bundleHash) {
    std::lock_guard<std::mutex> lock(mutex_);
    return store_.find(bundleHash) != store_.end();
}

std::vector<SecretStorageMetadata> MemorySecretStorageProvider::listSecrets() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SecretStorageMetadata> result;
    result.reserve(store_.size());
    for (const auto& [_, entry] : store_) {
        result.push_back(entry.metadata);
    }
    return result;
}

void MemorySecretStorageProvider::recoverSecret(const std::string& bundleHash,
                                                const std::string& recoveryPassphrase,
                                                const StorageOptions& options) {
    if (bundleHash.empty()) {
        throw SecretStorageException("Bundle hash cannot be empty");
    }
    if (recoveryPassphrase.empty()) {
        throw SecretStorageException("Recovery passphrase cannot be empty");
    }

    std::string raw;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = recoveryStore_.find(bundleHash);
        if (it == recoveryStore_.end()) {
            throw SecretStorageException::notFound(bundleHash);
        }
        raw = it->second;
    }

    EncryptedSecretPayload payload = EncryptedSecretPayload::fromString(raw);
    std::string secret = open(payload, recoveryPassphrase);

    StorageOptions storeOpts = options;
    storeOpts.recoveryPassphrase = recoveryPassphrase;

    storeSecret(bundleHash, secret, storeOpts);
    zeroizeString(secret);
}
} // namespace storage
} // namespace knishio