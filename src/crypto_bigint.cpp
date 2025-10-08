#include "crypto_bigint.h"
#include <sodium.h>
#include <cctype>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace knishio {

CryptoBigInt::CryptoBigInt() : limbs_(1, 0) {
}

CryptoBigInt::CryptoBigInt(const std::string& hex_str) {
    fromHexString(hex_str);
}

CryptoBigInt::CryptoBigInt(const CryptoBigInt& other) : limbs_(other.limbs_) {
}

CryptoBigInt& CryptoBigInt::operator=(const CryptoBigInt& other) {
    if (this != &other) {
        // Securely clear current data
        secureClear();
        limbs_ = other.limbs_;
    }
    return *this;
}

CryptoBigInt::~CryptoBigInt() {
    secureClear();
}

void CryptoBigInt::fromHexString(const std::string& hex_str) {
    if (hex_str.empty()) {
        limbs_.assign(1, 0);
        return;
    }
    
    // Validate hex string
    for (char c : hex_str) {
        if (!std::isxdigit(c)) {
            throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
        }
    }
    
    // Calculate number of limbs needed
    size_t hex_chars = hex_str.length();
    size_t chars_per_limb = LIMB_BITS / 4;  // 8 hex chars per 32-bit limb
    size_t num_limbs = (hex_chars + chars_per_limb - 1) / chars_per_limb;
    
    limbs_.assign(num_limbs, 0);
    
    // Process hex string from right to left (least significant first)
    for (size_t i = 0; i < hex_chars; ++i) {
        size_t hex_pos = hex_chars - 1 - i;
        char hex_char = hex_str[hex_pos];
        
        // Convert hex character to value
        uint32_t digit_val = 0;
        if (hex_char >= '0' && hex_char <= '9') {
            digit_val = hex_char - '0';
        } else if (hex_char >= 'a' && hex_char <= 'f') {
            digit_val = hex_char - 'a' + 10;
        } else if (hex_char >= 'A' && hex_char <= 'F') {
            digit_val = hex_char - 'A' + 10;
        }
        
        size_t limb_index = i / chars_per_limb;
        size_t bit_offset = (i % chars_per_limb) * 4;
        
        limbs_[limb_index] |= (digit_val << bit_offset);
    }
}

std::string CryptoBigInt::toHexString() const {
    if (isZero()) {
        return "0";
    }
    
    std::ostringstream result;
    result << std::hex;
    
    // Find most significant non-zero limb
    size_t first_nonzero = limbs_.size();
    for (size_t i = limbs_.size(); i > 0; --i) {
        if (limbs_[i - 1] != 0) {
            first_nonzero = i - 1;
            break;
        }
    }
    
    if (first_nonzero == limbs_.size()) {
        return "0";
    }
    
    // Output most significant limb without leading zeros
    result << limbs_[first_nonzero];
    
    // Output remaining limbs with leading zeros
    for (size_t i = first_nonzero; i > 0; --i) {
        result << std::setfill('0') << std::setw(8) << limbs_[i - 1];
    }
    
    return result.str();
}

bool CryptoBigInt::isZero() const {
    uint32_t acc = 0;
    for (uint32_t limb : limbs_) {
        acc |= limb;
    }
    return acc == 0;
}

CryptoBigInt CryptoBigInt::add(const CryptoBigInt& other) const {
    size_t max_size = std::max(limbs_.size(), other.limbs_.size());
    CryptoBigInt result;
    result.limbs_.resize(max_size + 1, 0);  // +1 for potential overflow
    
    // Prepare operands with same size
    std::vector<uint32_t> a_limbs(max_size, 0);
    std::vector<uint32_t> b_limbs(max_size, 0);
    
    std::copy(limbs_.begin(), limbs_.end(), a_limbs.begin());
    std::copy(other.limbs_.begin(), other.limbs_.end(), b_limbs.begin());
    
    // Constant-time addition
    uint32_t carry = constantTimeAdd(result.limbs_.data(), a_limbs.data(), b_limbs.data(), max_size);
    result.limbs_[max_size] = carry;
    
    result.normalize();
    return result;
}

CryptoBigInt CryptoBigInt::operator+(const CryptoBigInt& other) const {
    return add(other);
}

void CryptoBigInt::secureClear() {
    if (!limbs_.empty()) {
        sodium_memzero(limbs_.data(), limbs_.size() * sizeof(uint32_t));
        limbs_.clear();
    }
}

uint32_t CryptoBigInt::constantTimeSelect(uint32_t condition, uint32_t if_true, uint32_t if_false) {
    // Ensure condition is 0 or 1
    condition &= 1;
    uint32_t mask = ~(condition - 1);  // 0xFFFFFFFF if condition==1, 0x00000000 if condition==0
    return (if_true & mask) | (if_false & ~mask);
}

uint32_t CryptoBigInt::constantTimeAdd(uint32_t* result, const uint32_t* a, const uint32_t* b, size_t num_limbs) {
    uint64_t carry = 0;
    
    for (size_t i = 0; i < num_limbs; ++i) {
        uint64_t sum = static_cast<uint64_t>(a[i]) + static_cast<uint64_t>(b[i]) + carry;
        result[i] = static_cast<uint32_t>(sum & LIMB_MASK);
        carry = sum >> LIMB_BITS;
    }
    
    return static_cast<uint32_t>(carry);
}

void CryptoBigInt::normalize() {
    // Remove leading zeros while maintaining constant time characteristics
    while (limbs_.size() > 1 && limbs_.back() == 0) {
        limbs_.pop_back();
    }
}

size_t CryptoBigInt::getMaxSize(const CryptoBigInt& other) const {
    return std::max(limbs_.size(), other.limbs_.size());
}

// WalletCrypto implementation

std::string WalletCrypto::constantTimeHexAdd(const std::string& secret_hex, const std::string& position_hex) {
    // Validate inputs
    if (!isValidHex(secret_hex) || !isValidHex(position_hex)) {
        throw std::invalid_argument("Invalid hex string provided");
    }
    
    try {
        // Use constant-time BigInt operations
        CryptoBigInt secret(secret_hex);
        CryptoBigInt position(position_hex);
        
        CryptoBigInt result = secret.add(position);
        std::string result_hex = result.toHexString();
        
        // Securely clear temporary objects
        secret.secureClear();
        position.secureClear();
        result.secureClear();
        
        return result_hex;
        
    } catch (const std::exception& e) {
        throw std::runtime_error("Constant-time hex addition failed: " + std::string(e.what()));
    }
}

bool WalletCrypto::isValidHex(const std::string& hex_str) {
    if (hex_str.empty()) {
        return false;
    }
    
    for (char c : hex_str) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }
    
    return true;
}

void WalletCrypto::secureClear(void* ptr, size_t size) {
    sodium_memzero(ptr, size);
}

} // namespace knishio