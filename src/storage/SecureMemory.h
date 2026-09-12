#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <openssl/crypto.h>
#include <sodium.h>

namespace knishio {
namespace storage {

/**
 * Zeroize raw memory buffer
 */
inline void zeroize(void* ptr, size_t len) {
    if (ptr != nullptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

/**
 * Zeroize vector of bytes
 */
inline void zeroizeBytes(std::vector<uint8_t>& bytes) {
    if (!bytes.empty()) {
        OPENSSL_cleanse(bytes.data(), bytes.size());
        bytes.clear();
    }
}

/**
 * Zeroize std::string buffer
 */
inline void zeroizeString(std::string& str) {
    if (!str.empty()) {
        OPENSSL_cleanse(str.data(), str.size());
        str.clear();
    }
}

/**
 * RAII container for sensitive bytes that zeroizes upon destruction
 */
class SecureBytes {
public:
    SecureBytes() = default;
    
    explicit SecureBytes(size_t size) : data_(size, 0) {}
    
    SecureBytes(const uint8_t* data, size_t size) : data_(data, data + size) {}
    
    explicit SecureBytes(std::vector<uint8_t> data) : data_(std::move(data)) {}
    
    ~SecureBytes() {
        zeroizeBytes(data_);
    }

    // Non-copyable
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    // Movable
    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {}
    
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            zeroizeBytes(data_);
            data_ = std::move(other.data_);
        }
        return *this;
    }

    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] uint8_t* data() noexcept { return data_.data(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    
    [[nodiscard]] const std::vector<uint8_t>& get() const noexcept { return data_; }
    [[nodiscard]] std::vector<uint8_t>& get() noexcept { return data_; }

private:
    std::vector<uint8_t> data_;
};

/**
 * RAII container for sensitive string that zeroizes upon destruction
 */
class SecureString {
public:
    SecureString() = default;
    
    explicit SecureString(std::string str) : str_(std::move(str)) {}
    
    ~SecureString() {
        zeroizeString(str_);
    }

    // Non-copyable
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // Movable
    SecureString(SecureString&& other) noexcept : str_(std::move(other.str_)) {}
    
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            zeroizeString(str_);
            str_ = std::move(other.str_);
        }
        return *this;
    }

    [[nodiscard]] const char* c_str() const noexcept { return str_.c_str(); }
    [[nodiscard]] const std::string& str() const noexcept { return str_; }
    [[nodiscard]] size_t size() const noexcept { return str_.size(); }
    [[nodiscard]] bool empty() const noexcept { return str_.empty(); }

private:
    std::string str_;
};

/**
 * Execute callback with secure byte vector and guarantee zeroization afterwards
 */
template <typename F>
auto withSecureBytes(std::vector<uint8_t> bytes, F&& func) {
    struct Cleanup {
        std::vector<uint8_t>& ref;
        ~Cleanup() { zeroizeBytes(ref); }
    } cleanup{bytes};
    return std::forward<F>(func)(bytes);
}

/**
 * Execute callback with secure string and guarantee zeroization afterwards
 */
template <typename F>
auto withSecureString(std::string str, F&& func) {
    struct Cleanup {
        std::string& ref;
        ~Cleanup() { zeroizeString(ref); }
    } cleanup{str};
    return std::forward<F>(func)(str);
}

/**
 * Constant-time byte array comparison
 */
inline bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    if (a == nullptr || b == nullptr) {
        return a == b;
    }
    return CRYPTO_memcmp(a, b, len) == 0;
}

/**
 * Constant-time vector comparison
 */
inline bool constantTimeEquals(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return constantTimeEquals(a.data(), b.data(), a.size());
}

/**
 * Constant-time string comparison
 */
inline bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace storage
} // namespace knishio

namespace KnishIO {
namespace storage {
    using knishio::storage::zeroize;
    using knishio::storage::zeroizeBytes;
    using knishio::storage::zeroizeString;
    using knishio::storage::SecureBytes;
    using knishio::storage::SecureString;
    using knishio::storage::withSecureBytes;
    using knishio::storage::withSecureString;
    using knishio::storage::constantTimeEquals;
} // namespace storage
} // namespace KnishIO
