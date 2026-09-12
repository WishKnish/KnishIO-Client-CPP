#include "storage/SecretEnvelope.h"
#include "storage/SecretStorageProvider.h"
#include "storage/StorageBackend.h"
#include "storage/SecretStorageException.h"
#include "storage/SecureMemory.h"
#include "third_party/nlohmann/json.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <cstdlib>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using json = nlohmann::json;
using namespace knishio::storage;

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

json loadVectors() {
    std::vector<std::string> candidates;
    if (const char* env = std::getenv("KNISHIO_CROSS_PLATFORM_VECTORS")) {
        candidates.emplace_back(env);
    }
#ifdef KNISHIO_VECTORS_PATH
    candidates.emplace_back(KNISHIO_VECTORS_PATH);
#endif
    candidates.emplace_back("tests/fixtures/cross-platform-test-vectors.json");
    candidates.emplace_back("fixtures/cross-platform-test-vectors.json");
    if (const char* sd = std::getenv("KNISHIO_SHARED_RESULTS")) {
        candidates.emplace_back(std::string(sd) + "/cross-platform-test-vectors.json");
    }

    std::ifstream f;
    for (const auto& p : candidates) {
        f.open(p);
        if (f.is_open()) {
            break;
        }
        f.clear();
    }
    if (!f.is_open()) {
        throw std::runtime_error("cross-platform-test-vectors.json not found");
    }
    return json::parse(f);
}

} // anonymous namespace

int main() {
    std::cout << "Running KnishIO C++ Secret Storage tests..." << std::endl;

    // =========================================================================
    // 1. Secure Memory & Zeroization Tests
    // =========================================================================
    std::cout << "\n[1] Secure Memory & Zeroization" << std::endl;
    {
        std::vector<uint8_t> bytes = {1, 2, 3, 4, 5};
        zeroizeBytes(bytes);
        check(bytes.empty(), "zeroizeBytes clears vector");

        std::string str = "super-secret-password-123";
        zeroizeString(str);
        check(str.empty(), "zeroizeString clears string");

        check(constantTimeEquals("secret123", "secret123"), "constantTimeEquals positive string match");
        check(!constantTimeEquals("secret123", "secret124"), "constantTimeEquals negative string match (differing byte)");
        check(!constantTimeEquals("secret123", "secret12"), "constantTimeEquals negative string match (differing length)");

        std::vector<uint8_t> v1 = {0xAA, 0xBB, 0xCC};
        std::vector<uint8_t> v2 = {0xAA, 0xBB, 0xCC};
        std::vector<uint8_t> v3 = {0xAA, 0xBB, 0xDD};
        check(constantTimeEquals(v1, v2), "constantTimeEquals positive vector match");
        check(!constantTimeEquals(v1, v3), "constantTimeEquals negative vector match");

        bool callbackRan = false;
        withSecureString("temporary-secret", [&](const std::string& sec) {
            callbackRan = true;
            check(sec == "temporary-secret", "withSecureString passes correct string");
        });
        check(callbackRan, "withSecureString executes callback");
    }

    // =========================================================================
    // 2. Cross-Platform Test Vector Decryption
    // =========================================================================
    std::cout << "\n[2] Cross-Platform Test Vector Decryption" << std::endl;
    json vectors;
    try {
        vectors = loadVectors();
        check(true, "Loaded cross-platform-test-vectors.json");
    } catch (const std::exception& e) {
        check(false, "Load cross-platform-test-vectors.json", e.what());
        return 1;
    }

    try {
        const auto& testVector = vectors.at("vectors").at("secret_storage_envelope").at("tests").at(0);
        const auto passphrase = testVector.at("passphrase").get<std::string>();
        const auto expectedPlaintext = testVector.at("expectedPlaintext").get<std::string>();
        const auto payloadJson = testVector.at("payload");

        EncryptedSecretPayload payload = EncryptedSecretPayload::fromJson(payloadJson);
        check(payload.version == 1, "Payload version is 1");
        check(payload.algorithm == "AES-GCM", "Payload algorithm is AES-GCM");
        check(payload.iterations == 100000, "Payload iterations is 100000");
        check(payload.metadata.providerType == "webcrypto-aes-gcm", "Payload providerType parsed correctly");
        check(payload.metadata.hardwareBacked == false, "Payload hardwareBacked parsed as false");

        std::string decrypted = open(payload, passphrase);
        check(decrypted == expectedPlaintext,
              "Decrypt frozen TypeScript envelope matches expected plaintext",
              "got: " + decrypted + ", expected: " + expectedPlaintext);
    } catch (const std::exception& e) {
        check(false, "Cross-platform test vector decryption", e.what());
    }

    // =========================================================================
    // 3. Emitted Metadata Keys Contract
    // =========================================================================
    std::cout << "\n[3] Metadata Keys Contract (camelCase wire format)" << std::endl;
    try {
        auto backend = std::make_shared<MemoryStorageBackend>();
        AesGcmSecretStorageProvider provider(backend, "test-passphrase");

        const std::string bundle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const std::string secret = "test-secret-payload-data";

        // Store without label
        provider.storeSecret(bundle, secret, StorageOptions::withPassphrase("test-passphrase"));

        auto raw = backend->getItem(std::string(AesGcmSecretStorageProvider::KEY_PREFIX) + bundle);
        check(raw.has_value(), "Envelope was persisted to storage backend");

        json storedJson = json::parse(*raw);
        check(storedJson.contains("metadata"), "Stored envelope contains metadata object");

        const auto& metaJson = storedJson.at("metadata");

        // Required keys MUST be present in camelCase
        const std::vector<std::string> requiredKeys = {
            "bundleHash", "createdAt", "hardwareBacked", "providerType"
        };
        for (const auto& key : requiredKeys) {
            check(metaJson.contains(key), "Emitted metadata contains required key: " + key);
        }

        // Forbidden keys MUST NOT be present (snake_case divergence check)
        const std::vector<std::string> forbiddenKeys = {
            "bundle_hash", "created_at", "hardware_backed", "provider_type"
        };
        for (const auto& key : forbiddenKeys) {
            check(!metaJson.contains(key), "Emitted metadata does NOT contain forbidden snake_case key: " + key);
        }

        // Optional key 'label' MUST be omitted when unset, NEVER emitted as null
        check(!metaJson.contains("label"), "Emitted metadata omits optional 'label' when unset (never null)");

        // Now store with label and verify it is emitted
        const std::string bundleWithLabel = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        StorageOptions optsWithLabel;
        optsWithLabel.label = "production-wallet";
        optsWithLabel.passphrase = "test-passphrase";
        provider.storeSecret(bundleWithLabel, secret, optsWithLabel);

        auto rawWithLabel = backend->getItem(std::string(AesGcmSecretStorageProvider::KEY_PREFIX) + bundleWithLabel);
        json storedJsonWithLabel = json::parse(*rawWithLabel);
        check(storedJsonWithLabel.at("metadata").contains("label"), "Emitted metadata contains 'label' when set");
        check(storedJsonWithLabel.at("metadata").at("label") == "production-wallet", "Emitted 'label' matches value");
        check(storedJsonWithLabel.at("metadata").at("hardwareBacked") == false, "hardwareBacked is false for software provider");
        check(storedJsonWithLabel.at("metadata").at("providerType") == "aes-gcm", "providerType is 'aes-gcm'");
    } catch (const std::exception& e) {
        check(false, "Metadata keys contract", e.what());
    }

    // =========================================================================
    // 4. Round Trip, Wrong Passphrase, Corrupted Payload
    // =========================================================================
    std::cout << "\n[4] Round Trip, Wrong Passphrase & Corruption" << std::endl;
    try {
        SecretStorageMetadata meta;
        meta.bundleHash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        meta.createdAt = 1700000000000LL;
        meta.hardwareBacked = false;
        meta.providerType = "aes-gcm";

        const std::string secret = "SUPER-SECRET-MASTER-KEY-007";
        const std::string pass = "correct-horse-battery-staple";

        EncryptedSecretPayload payload = seal(secret, pass, meta);
        check(!payload.ciphertext.empty(), "Sealed payload ciphertext is non-empty");
        check(!payload.iv.empty(), "Sealed payload IV is non-empty");
        check(!payload.salt.empty(), "Sealed payload salt is non-empty");

        // Decrypt with correct passphrase
        std::string recovered = open(payload, pass);
        check(recovered == secret, "Round trip decryption with correct passphrase matches original");

        // Decrypt with wrong passphrase -> must fail
        bool wrongPassFailed = false;
        try {
            open(payload, "incorrect-passphrase");
        } catch (const SecretStorageException&) {
            wrongPassFailed = true;
        }
        check(wrongPassFailed, "Decryption fails with wrong passphrase (tag mismatch)");

        // Corrupted ciphertext -> must fail
        bool corruptedCiphertextFailed = false;
        try {
            EncryptedSecretPayload corrupted = payload;
            // Modify first character of ciphertext
            corrupted.ciphertext[0] = (corrupted.ciphertext[0] == 'A') ? 'B' : 'A';
            open(corrupted, pass);
        } catch (const SecretStorageException&) {
            corruptedCiphertextFailed = true;
        }
        check(corruptedCiphertextFailed, "Decryption fails with corrupted ciphertext");

        // Corrupted IV -> must fail
        bool corruptedIvFailed = false;
        try {
            EncryptedSecretPayload corrupted = payload;
            corrupted.iv[0] = (corrupted.iv[0] == 'A') ? 'B' : 'A';
            open(corrupted, pass);
        } catch (const SecretStorageException&) {
            corruptedIvFailed = true;
        }
        check(corruptedIvFailed, "Decryption fails with corrupted IV");

        // Malformed JSON string
        bool malformedJsonFailed = false;
        try {
            EncryptedSecretPayload::fromString("{not a valid json");
        } catch (const SecretStorageException&) {
            malformedJsonFailed = true;
        }
        check(malformedJsonFailed, "EncryptedSecretPayload::fromString rejects invalid JSON");
    } catch (const std::exception& e) {
        check(false, "Round trip / wrong passphrase / corruption test", e.what());
    }

    // =========================================================================
    // 5. Storage Backend (Memory & File with 0600 Permissions)
    // =========================================================================
    std::cout << "\n[5] Storage Backends (Memory & File)" << std::endl;
    try {
        // MemoryStorageBackend
        MemoryStorageBackend mem;
        check(!mem.getItem("nonexistent").has_value(), "MemoryStorageBackend getItem nonexistent is nullopt");
        mem.setItem("key1", "val1");
        check(mem.getItem("key1") == "val1", "MemoryStorageBackend get/set works");
        check(mem.keys().size() == 1, "MemoryStorageBackend keys count 1");
        check(mem.removeItem("key1"), "MemoryStorageBackend removeItem returns true");
        check(!mem.getItem("key1").has_value(), "MemoryStorageBackend removeItem deletes item");

        // FileStorageBackend
        std::filesystem::path tmpDir = std::filesystem::temp_directory_path();
        std::filesystem::path testFile = tmpDir / ("knishio_test_store_" + std::to_string(std::rand()) + ".json");

        // Clean up before test if exists
        std::filesystem::remove(testFile);

        {
            FileStorageBackend fileBackend(testFile);
            check(!fileBackend.getItem("keyA").has_value(), "FileStorageBackend getItem nonexistent is nullopt");
            fileBackend.setItem("keyA", "valA");
            check(fileBackend.getItem("keyA") == "valA", "FileStorageBackend get/set works");
            check(std::filesystem::exists(testFile), "FileStorageBackend created file on disk");

#ifndef _WIN32
            // Verify file permissions are 0600 (owner read+write only)
            struct stat st;
            if (stat(testFile.c_str(), &st) == 0) {
                mode_t perms = st.st_mode & 0777;
                check(perms == 0600, "FileStorageBackend file permissions are 0600 (got " +
                      std::to_string(perms) + ")");
            }
#endif
        }

        // Reopen from disk to prove persistence
        {
            FileStorageBackend fileBackend2(testFile);
            check(fileBackend2.getItem("keyA") == "valA", "FileStorageBackend persists data across re-instantiation");
            fileBackend2.setItem("keyB", "valB");
            check(fileBackend2.keys().size() == 2, "FileStorageBackend has 2 keys");
            check(fileBackend2.removeItem("keyA"), "FileStorageBackend removes keyA");
            check(!fileBackend2.getItem("keyA").has_value(), "FileStorageBackend keyA is removed");
        }

        // Reopen again and check keyA is gone, keyB remains
        {
            FileStorageBackend fileBackend3(testFile);
            check(!fileBackend3.getItem("keyA").has_value(), "FileStorageBackend keyA remained removed on disk");
            check(fileBackend3.getItem("keyB") == "valB", "FileStorageBackend keyB remained intact");
        }

        // Clean up test file
        std::filesystem::remove(testFile);
    } catch (const std::exception& e) {
        check(false, "Storage backend test", e.what());
    }

    // =========================================================================
    // 6. Provider Operations & Client Lifecycle
    // =========================================================================
    std::cout << "\n[6] Provider Operations & Lifecycle" << std::endl;
    try {
        auto backend = std::make_shared<MemoryStorageBackend>();
        AesGcmSecretStorageProvider provider(backend, "default-passphrase");

        check(provider.providerType() == "aes-gcm", "Provider type is aes-gcm");
        check(!provider.isHardwareBacked(), "Provider is not hardware backed");
        check(provider.isAvailable(), "Provider is available");

        const std::string bundle1 = "1111111111111111111111111111111111111111111111111111111111111111";
        const std::string secret1 = "secret-content-alpha";
        const std::string bundle2 = "2222222222222222222222222222222222222222222222222222222222222222";
        const std::string secret2 = "secret-content-beta";

        check(!provider.hasSecret(bundle1), "hasSecret false before storing");
        provider.storeSecret(bundle1, secret1);
        check(provider.hasSecret(bundle1), "hasSecret true after storing");

        StorageOptions customOpts;
        customOpts.label = "beta-key";
        customOpts.passphrase = "custom-passphrase";
        provider.storeSecret(bundle2, secret2, customOpts);

        // Retrieve secret 1 with default passphrase
        auto retrieved1 = provider.retrieveSecret(bundle1);
        check(retrieved1.has_value() && *retrieved1 == secret1, "retrieveSecret bundle1 succeeds with default passphrase");

        // Retrieve secret 2 with custom passphrase
        auto retrieved2 = provider.retrieveSecret(bundle2, customOpts);
        check(retrieved2.has_value() && *retrieved2 == secret2, "retrieveSecret bundle2 succeeds with custom passphrase");

        // withSecret execution and memory zeroization
        bool withSecretRan = false;
        provider.withSecret(bundle1, {}, [&](const std::string& sec) {
            withSecretRan = true;
            check(sec == secret1, "withSecret passes correct secret string");
        });
        check(withSecretRan, "withSecret callback executed");

        // withSecret on missing bundle throws notFound
        bool notFoundThrown = false;
        try {
            provider.withSecret("missing-bundle", {}, [](const std::string&) {});
        } catch (const SecretStorageException&) {
            notFoundThrown = true;
        }
        check(notFoundThrown, "withSecret throws SecretStorageException for missing bundle");

        // listSecrets
        auto secretsList = provider.listSecrets();
        check(secretsList.size() == 2, "listSecrets returns 2 metadata items");

        // deleteSecret
        check(provider.deleteSecret(bundle1), "deleteSecret returns true");
        check(!provider.hasSecret(bundle1), "hasSecret false after delete");
        check(!provider.retrieveSecret(bundle1).has_value(), "retrieveSecret returns nullopt after delete");
        check(provider.listSecrets().size() == 1, "listSecrets returns 1 metadata item after delete");

        // MemorySecretStorageProvider
        MemorySecretStorageProvider memProvider;
        check(memProvider.providerType() == "memory", "MemorySecretStorageProvider type is memory");
        memProvider.storeSecret(bundle1, secret1);
        check(memProvider.hasSecret(bundle1), "MemorySecretStorageProvider hasSecret");
        check(memProvider.retrieveSecret(bundle1) == secret1, "MemorySecretStorageProvider retrieveSecret");
        check(memProvider.deleteSecret(bundle1), "MemorySecretStorageProvider deleteSecret");
    } catch (const std::exception& e) {
        check(false, "Provider operations test", e.what());
    }


    // =========================================================================
    // 7. Secret Recovery Contract (RECOVERY_KEY_PREFIX & re-enrollment)
    // =========================================================================
    std::cout << "\n[7] Secret Recovery Contract & Re-enrollment" << std::endl;
    try {
        // Constant & options checks
        check(std::string(RECOVERY_KEY_PREFIX) == "knishio:recovery:", "RECOVERY_KEY_PREFIX constant is 'knishio:recovery:'");
        check(std::string(SECRET_KEY_PREFIX) == "knishio:secret:", "SECRET_KEY_PREFIX constant is 'knishio:secret:'");

        StorageOptions defaultOpts;
        check(!defaultOpts.recoveryPassphrase.has_value(), "StorageOptions default recoveryPassphrase is nullopt");
        check(!defaultOpts.allowUnrecoverable, "StorageOptions default allowUnrecoverable is false");

        auto recoveryOpts = StorageOptions::withRecovery("main-pass", "recov-pass");
        check(recoveryOpts.passphrase == "main-pass", "withRecovery sets passphrase");
        check(recoveryOpts.recoveryPassphrase == "recov-pass", "withRecovery sets recoveryPassphrase");

        // AesGcmSecretStorageProvider recovery lifecycle
        auto backend = std::make_shared<MemoryStorageBackend>();
        AesGcmSecretStorageProvider provider(backend, "default-pass");

        const std::string bundle = "3333333333333333333333333333333333333333333333333333333333333333";
        const std::string secret = "RECOVERABLE-MASTER-SECRET-PAYLOAD-999";
        const std::string mainPass = "primary-strong-passphrase";
        const std::string recPass = "emergency-recovery-phrase-xyz";

        StorageOptions storeOpts;
        storeOpts.passphrase = mainPass;
        storeOpts.recoveryPassphrase = recPass;
        storeOpts.label = "recovery-test-key";

        provider.storeSecret(bundle, secret, storeOpts);

        // Verify both primary and recovery envelopes were persisted
        auto primaryRaw = backend->getItem(std::string(SECRET_KEY_PREFIX) + bundle);
        auto recoveryRaw = backend->getItem(std::string(RECOVERY_KEY_PREFIX) + bundle);
        check(primaryRaw.has_value(), "Primary envelope was written to knishio:secret:<bundle>");
        check(recoveryRaw.has_value(), "Recovery envelope was written to knishio:recovery:<bundle>");

        // Inspect recovery envelope metadata
        json recoveryJson = json::parse(*recoveryRaw);
        check(recoveryJson.contains("metadata"), "Recovery envelope has metadata");
        const auto& recMeta = recoveryJson.at("metadata");
        check(recMeta.at("providerType") == "aes-gcm", "Recovery envelope providerType is 'aes-gcm'");
        check(recMeta.at("hardwareBacked") == false, "Recovery envelope hardwareBacked is false");
        check(recMeta.at("bundleHash") == bundle, "Recovery envelope bundleHash matches");
        check(recMeta.at("label") == "recovery-test-key", "Recovery envelope label matches");

        // Verify listSecrets ignores recovery records
        auto list = provider.listSecrets();
        check(list.size() == 1, "listSecrets returns exactly 1 item (ignoring knishio:recovery:)");
        check(list[0].bundleHash == bundle, "listSecrets item is the primary secret");

        // Simulate primary KEK / envelope loss (e.g. wiped hardware key or corrupted primary)
        backend->removeItem(std::string(SECRET_KEY_PREFIX) + bundle);
        check(!provider.hasSecret(bundle), "hasSecret false after primary envelope loss");
        check(!provider.retrieveSecret(bundle, StorageOptions::withPassphrase(mainPass)).has_value(),
              "retrieveSecret returns nullopt when primary envelope is missing");

        // Attempt recoverSecret with wrong recovery passphrase -> must fail closed
        bool wrongPassFailed = false;
        try {
            provider.recoverSecret(bundle, "wrong-recovery-passphrase");
        } catch (const SecretStorageException&) {
            wrongPassFailed = true;
        }
        check(wrongPassFailed, "recoverSecret fails closed with wrong recovery passphrase");

        // Attempt recoverSecret with nonexistent bundle -> must fail closed
        bool notFoundFailed = false;
        try {
            provider.recoverSecret("nonexistent-bundle-hash", recPass);
        } catch (const SecretStorageException&) {
            notFoundFailed = true;
        }
        check(notFoundFailed, "recoverSecret fails with notFound for missing recovery record");

        // Attempt recoverSecret with empty passphrase or bundle -> must throw
        bool emptyPassFailed = false;
        try {
            provider.recoverSecret(bundle, "");
        } catch (const SecretStorageException&) {
            emptyPassFailed = true;
        }
        check(emptyPassFailed, "recoverSecret rejects empty recovery passphrase");

        // Successful recovery: re-enrolls under primary provider
        provider.recoverSecret(bundle, recPass, StorageOptions::withPassphrase("new-primary-pass"));
        check(provider.hasSecret(bundle), "hasSecret true after recoverSecret");

        auto recoveredSecret = provider.retrieveSecret(bundle, StorageOptions::withPassphrase("new-primary-pass"));
        check(recoveredSecret.has_value() && *recoveredSecret == secret,
              "retrieveSecret with new primary passphrase returns byte-identical secret");

        // Primary ciphertext re-enrolled is a fresh ciphertext
        auto newPrimaryRaw = backend->getItem(std::string(SECRET_KEY_PREFIX) + bundle);
        check(newPrimaryRaw.has_value() && *newPrimaryRaw != *primaryRaw,
              "Re-enrolled primary envelope has fresh ciphertext/salt/IV");

        // deleteSecret removes BOTH primary and recovery records
        check(backend->getItem(std::string(RECOVERY_KEY_PREFIX) + bundle).has_value(),
              "Recovery envelope still present prior to deleteSecret");
        bool deleted = provider.deleteSecret(bundle);
        check(deleted, "deleteSecret returns true");
        check(!backend->getItem(std::string(SECRET_KEY_PREFIX) + bundle).has_value(),
              "deleteSecret removed primary record knishio:secret:<bundle>");
        check(!backend->getItem(std::string(RECOVERY_KEY_PREFIX) + bundle).has_value(),
              "deleteSecret removed recovery record knishio:recovery:<bundle>");
        check(!provider.hasSecret(bundle), "hasSecret false after deleteSecret");

        // MemorySecretStorageProvider recovery lifecycle
        MemorySecretStorageProvider memProvider;
        const std::string memBundle = "4444444444444444444444444444444444444444444444444444444444444444";
        const std::string memSecret = "MEMORY-RECOVERABLE-SECRET-555";
        const std::string memRecPass = "mem-recovery-pass-789";

        StorageOptions memOpts;
        memOpts.recoveryPassphrase = memRecPass;
        memOpts.label = "mem-rec-label";
        memProvider.storeSecret(memBundle, memSecret, memOpts);

        check(memProvider.hasSecret(memBundle), "MemorySecretStorageProvider hasSecret true");
        check(memProvider.listSecrets().size() == 1, "MemorySecretStorageProvider listSecrets has 1 item");

        // Recover in MemorySecretStorageProvider with bad passphrase
        bool memBadPassFailed = false;
        try {
            memProvider.recoverSecret(memBundle, "incorrect-pass");
        } catch (const SecretStorageException&) {
            memBadPassFailed = true;
        }
        check(memBadPassFailed, "MemorySecretStorageProvider recoverSecret fails with wrong passphrase");

        // Recover with correct passphrase
        memProvider.recoverSecret(memBundle, memRecPass);
        check(memProvider.retrieveSecret(memBundle) == memSecret,
              "MemorySecretStorageProvider recoverSecret restores secret");

        // deleteSecret removes primary & recovery
        check(memProvider.deleteSecret(memBundle), "MemorySecretStorageProvider deleteSecret returns true");
        check(!memProvider.hasSecret(memBundle), "MemorySecretStorageProvider hasSecret false after delete");
        bool memNotFoundAfterDelete = false;
        try {
            memProvider.recoverSecret(memBundle, memRecPass);
        } catch (const SecretStorageException&) {
            memNotFoundAfterDelete = true;
        }
        check(memNotFoundAfterDelete, "MemorySecretStorageProvider recoverSecret fails after deleteSecret");
    } catch (const std::exception& e) {
        check(false, "Secret recovery contract test", e.what());
    }
    std::cout << "\n----------------------------------------" << std::endl;
    if (failures == 0) {
        std::cout << "\033[0;32mALL SECRET STORAGE TESTS PASSED!\033[0m" << std::endl;
        return 0;
    } else {
        std::cout << "\033[0;31mFAILED: " << failures << " test(s) failed!\033[0m" << std::endl;
        return 1;
    }
}
