#pragma once

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>  // uint32_t/uint8_t — transitively included on macOS, NOT on Linux (cycle 127)

namespace knishio {

/**
 * Constant-time BigInt operations for cryptographic use
 * 
 * This class provides constant-time implementations of BigInt operations
 * to prevent timing attacks when handling cryptographic secrets.
 * 
 * SECURITY NOTE: All operations in this class are designed to execute
 * in constant time regardless of input values to prevent timing attacks.
 */
class CryptoBigInt {
private:
    std::vector<uint32_t> limbs_;
    static const size_t LIMB_BITS = 32;
    static const uint32_t LIMB_MASK = 0xFFFFFFFF;

public:
    /**
     * Constructor from hex string
     * @param hex_str Hexadecimal string representation
     */
    explicit CryptoBigInt(const std::string& hex_str);
    
    /**
     * Default constructor (zero)
     */
    CryptoBigInt();
    
    /**
     * Copy constructor
     */
    CryptoBigInt(const CryptoBigInt& other);
    
    /**
     * Assignment operator
     */
    CryptoBigInt& operator=(const CryptoBigInt& other);
    
    /**
     * Destructor - securely clears memory
     */
    ~CryptoBigInt();
    
    /**
     * Constant-time addition
     * @param other The value to add
     * @return Result of addition
     */
    CryptoBigInt add(const CryptoBigInt& other) const;
    
    /**
     * Operator+ for convenience (delegates to constant-time add)
     */
    CryptoBigInt operator+(const CryptoBigInt& other) const;
    
    /**
     * Convert to hexadecimal string
     * @return Hex string representation
     */
    std::string toHexString() const;
    
    /**
     * Check if zero (constant-time)
     * @return true if zero, false otherwise
     */
    bool isZero() const;
    
    /**
     * Securely clear all internal memory
     */
    void secureClear();
    
private:
    /**
     * Convert hex string to limbs array
     * @param hex_str Input hex string
     */
    void fromHexString(const std::string& hex_str);
    
    /**
     * Constant-time conditional select
     * @param condition Selection condition (must be 0 or 1)
     * @param if_true Value if condition is true
     * @param if_false Value if condition is false
     * @return Selected value
     */
    static uint32_t constantTimeSelect(uint32_t condition, uint32_t if_true, uint32_t if_false);
    
    /**
     * Constant-time addition of two limb arrays
     * @param result Output array
     * @param a First operand
     * @param b Second operand
     * @param num_limbs Number of limbs to process
     * @return Final carry bit
     */
    static uint32_t constantTimeAdd(uint32_t* result, const uint32_t* a, const uint32_t* b, size_t num_limbs);
    
    /**
     * Normalize limbs array size (remove leading zeros while maintaining constant time)
     */
    void normalize();
    
    /**
     * Get maximum size needed for operations
     */
    size_t getMaxSize(const CryptoBigInt& other) const;
};

/**
 * Constant-time BigInt operations specifically for wallet key generation
 */
class WalletCrypto {
public:
    /**
     * Constant-time addition of hex strings for wallet key generation
     * This replaces the vulnerable BigInt addition in generateWalletKey
     * 
     * @param secret_hex Secret as hex string
     * @param position_hex Position as hex string
     * @return Sum as hex string
     */
    static std::string constantTimeHexAdd(const std::string& secret_hex, const std::string& position_hex);
    
    /**
     * Validate hex string format
     * @param hex_str String to validate
     * @return true if valid hex, false otherwise
     */
    static bool isValidHex(const std::string& hex_str);
    
private:
    /**
     * Secure memory clearing utility
     * @param ptr Pointer to memory to clear
     * @param size Number of bytes to clear
     */
    static void secureClear(void* ptr, size_t size);
};

} // namespace knishio