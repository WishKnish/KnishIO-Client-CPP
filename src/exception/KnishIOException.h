#pragma once

#include <stdexcept>
#include <string>

namespace knishio {

/**
 * Base exception class for all KnishIO SDK exceptions
 */
class KnishIOException : public std::runtime_error {
public:
    explicit KnishIOException(const std::string& message)
        : std::runtime_error("[KnishIO] " + message) {}
    
    KnishIOException(const std::string& message, int errorCode)
        : std::runtime_error("[KnishIO] " + message + " (Error Code: " + std::to_string(errorCode) + ")"),
          errorCode_(errorCode) {}
    
    [[nodiscard]] int getErrorCode() const noexcept {
        return errorCode_;
    }
    
protected:
    int errorCode_ = 0;
};

/**
 * Exception thrown when cryptographic operations fail
 */
class CryptoException : public KnishIOException {
public:
    explicit CryptoException(const std::string& message)
        : KnishIOException("Crypto Error: " + message) {}
};

/**
 * Exception thrown when wallet operations fail
 */
class WalletException : public KnishIOException {
public:
    explicit WalletException(const std::string& message)
        : KnishIOException("Wallet Error: " + message) {}
};

/**
 * Exception thrown when molecule validation fails
 */
class MoleculeException : public KnishIOException {
public:
    explicit MoleculeException(const std::string& message)
        : KnishIOException("Molecule Error: " + message) {}
};

/**
 * Exception thrown when authentication fails
 */
class AuthenticationException : public KnishIOException {
public:
    explicit AuthenticationException(const std::string& message)
        : KnishIOException("Authentication Error: " + message) {}
};

/**
 * Exception thrown when network operations fail
 */
class NetworkException : public KnishIOException {
public:
    explicit NetworkException(const std::string& message)
        : KnishIOException("Network Error: " + message) {}
    
    NetworkException(const std::string& message, int httpStatus)
        : KnishIOException("Network Error: " + message, httpStatus) {}
};

/**
 * Exception thrown when validation fails
 */
class ValidationException : public KnishIOException {
public:
    explicit ValidationException(const std::string& message)
        : KnishIOException("Validation Error: " + message) {}
};

} // namespace knishio