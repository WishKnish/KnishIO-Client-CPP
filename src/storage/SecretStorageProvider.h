#pragma once

#include "storage/StorageBackend.h"
#include "storage/SecretEnvelope.h"
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <functional>

namespace knishio {
namespace storage {
constexpr const char* SECRET_KEY_PREFIX = "knishio:secret:";
constexpr const char* RECOVERY_KEY_PREFIX = "knishio:recovery:";

/**
 * Options for secret storage operations
 */
struct StorageOptions {
    std::optional<std::string> label;
    std::optional<std::string> passphrase;
    std::optional<std::string> recoveryPassphrase;
    bool allowUnrecoverable = false;

    StorageOptions() = default;

    StorageOptions(std::optional<std::string> lbl,
                   std::optional<std::string> pass,
                   std::optional<std::string> recPass = std::nullopt,
                   bool unrecoverable = false)
        : label(std::move(lbl)),
          passphrase(std::move(pass)),
          recoveryPassphrase(std::move(recPass)),
          allowUnrecoverable(unrecoverable) {}

    static StorageOptions withPassphrase(std::string pass) {
        StorageOptions opts;
        opts.passphrase = std::move(pass);
        return opts;
    }

    static StorageOptions withRecovery(std::string pass, std::string recPass) {
        StorageOptions opts;
        opts.passphrase = std::move(pass);
        opts.recoveryPassphrase = std::move(recPass);
        return opts;
    }
};

/**
 * Contract for hardware-compatible envelope encryption secret storage providers
 */
class SecretStorageProvider {
public:
    virtual ~SecretStorageProvider() = default;

    /**
     * Identifier of this provider type
     */
    [[nodiscard]] virtual std::string providerType() const = 0;

    /**
     * True only when this provider holds a non-exportable key inside platform-secure
     * hardware (Android TEE/StrongBox, Secure Enclave, TPM) and learned that from the
     * platform itself — never from a caller argument. Software envelope providers
     * return false. The value is persisted as metadata.hardwareBacked in every
     * envelope this provider writes.
     */
    [[nodiscard]] virtual bool isHardwareBacked() const = 0;

    /**
     * Whether this provider is available in the current environment
     */
    virtual bool isAvailable() = 0;

    /**
     * Store and encrypt a master secret for the given bundle hash
     */
    virtual void storeSecret(const std::string& bundleHash,
                             const std::string& secret,
                             const StorageOptions& options = {}) = 0;

    /**
     * Retrieve and decrypt the master secret for the given bundle hash
     */
    virtual std::optional<std::string> retrieveSecret(const std::string& bundleHash,
                                                     const StorageOptions& options = {}) = 0;

    /**
     * Delete a stored secret
     */
    virtual bool deleteSecret(const std::string& bundleHash) = 0;

    /**
     * Check if a secret exists for the given bundle hash
     */
    virtual bool hasSecret(const std::string& bundleHash) = 0;

    /**
     * List all stored secret metadata without exposing plaintext secrets
     */
    virtual std::vector<SecretStorageMetadata> listSecrets() = 0;

    /**
     * Execute a callback with the unwrapped secret and zeroize memory upon completion
     */
    virtual void withSecret(const std::string& bundleHash,
                            const StorageOptions& options,
                            const std::function<void(const std::string&)>& callback);

    /**
     * Recover a secret using its recovery envelope and re-enroll it
     */
    virtual void recoverSecret(const std::string& bundleHash,
                               const std::string& recoveryPassphrase,
                               const StorageOptions& options = {}) = 0;
};

/**
 * Software AES-GCM envelope encryption secret storage provider (never hardware-backed)
 */
class AesGcmSecretStorageProvider : public SecretStorageProvider {
public:
    static constexpr const char* KEY_PREFIX = SECRET_KEY_PREFIX;
    static constexpr const char* RECOVERY_PREFIX = RECOVERY_KEY_PREFIX;

    explicit AesGcmSecretStorageProvider(std::shared_ptr<StorageBackend> backend = nullptr,
                                         std::optional<std::string> defaultPassphrase = std::nullopt);
    ~AesGcmSecretStorageProvider() override = default;

    [[nodiscard]] std::string providerType() const override { return "aes-gcm"; }
    [[nodiscard]] bool isHardwareBacked() const override { return false; }
    bool isAvailable() override { return true; }

    void storeSecret(const std::string& bundleHash,
                     const std::string& secret,
                     const StorageOptions& options = {}) override;

    std::optional<std::string> retrieveSecret(const std::string& bundleHash,
                                              const StorageOptions& options = {}) override;

    bool deleteSecret(const std::string& bundleHash) override;
    bool hasSecret(const std::string& bundleHash) override;
    std::vector<SecretStorageMetadata> listSecrets() override;

    [[nodiscard]] std::shared_ptr<StorageBackend> backend() const noexcept { return backend_; }
    void recoverSecret(const std::string& bundleHash,
                       const std::string& recoveryPassphrase,
                       const StorageOptions& options = {}) override;


private:
    std::shared_ptr<StorageBackend> backend_;
    std::optional<std::string> defaultPassphrase_;
};

/**
 * Thread-safe in-memory secret storage provider for testing
 */
class MemorySecretStorageProvider : public SecretStorageProvider {
public:
    MemorySecretStorageProvider() = default;
    ~MemorySecretStorageProvider() override = default;

    [[nodiscard]] std::string providerType() const override { return "memory"; }
    [[nodiscard]] bool isHardwareBacked() const override { return false; }
    bool isAvailable() override { return true; }

    void storeSecret(const std::string& bundleHash,
                     const std::string& secret,
                     const StorageOptions& options = {}) override;

    std::optional<std::string> retrieveSecret(const std::string& bundleHash,
                                              const StorageOptions& options = {}) override;

    bool deleteSecret(const std::string& bundleHash) override;
    bool hasSecret(const std::string& bundleHash) override;
    std::vector<SecretStorageMetadata> listSecrets() override;

    void recoverSecret(const std::string& bundleHash,
                       const std::string& recoveryPassphrase,
                       const StorageOptions& options = {}) override;

    void clear();

private:
    struct Entry {
        std::string secret;
        SecretStorageMetadata metadata;
    };
    std::map<std::string, Entry> store_;
    mutable std::mutex mutex_;
    std::map<std::string, std::string> recoveryStore_;
};

} // namespace storage
} // namespace knishio

namespace KnishIO {
namespace storage {
    using knishio::storage::StorageOptions;
    using knishio::storage::SecretStorageProvider;
    using knishio::storage::AesGcmSecretStorageProvider;
    using knishio::storage::MemorySecretStorageProvider;
    using knishio::storage::SECRET_KEY_PREFIX;
    using knishio::storage::RECOVERY_KEY_PREFIX;
} // namespace storage
} // namespace KnishIO
