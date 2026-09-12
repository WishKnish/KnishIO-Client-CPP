#pragma once

#include "exception/KnishIOException.h"
#include <string>

namespace knishio {
namespace storage {

/**
 * Exception thrown when secret storage operations fail
 */
class SecretStorageException : public KnishIOException {
public:
    explicit SecretStorageException(const std::string& message)
        : KnishIOException("Secret Storage Error: " + message) {}

    static SecretStorageException notFound(const std::string& bundleHash) {
        return SecretStorageException("Secret not found for bundle: " + bundleHash);
    }

    static SecretStorageException decryptionFailed(const std::string& reason) {
        return SecretStorageException("Decryption failed: " + reason);
    }

    static SecretStorageException unavailable(const std::string& provider, const std::string& reason) {
        return SecretStorageException("Provider '" + provider + "' unavailable: " + reason);
    }
};

} // namespace storage
} // namespace knishio

namespace KnishIO {
namespace storage {
    using knishio::storage::SecretStorageException;
} // namespace storage
} // namespace KnishIO
