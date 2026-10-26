#include "utility.h"

#include "third_party/Keccak/Keccak.h"

#include <algorithm>
#include <cstdint>
#include <random>
#include <codecvt>
#include <sodium.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cctype>
#include <cmath>
#include <cstring>  // strlen — transitively included on macOS, NOT on Linux (cycle 127)

std::string charsetBaseConvert(const std::string &hashHex, unsigned int baseFrom, unsigned int baseTo, const char *baseToSymbolTable)
{
	// Validate input parameters
	if (hashHex.empty()) {
		return std::string();
	}

	if (baseToSymbolTable == nullptr) {
		throw std::invalid_argument("Symbol table cannot be null");
	}

	if (baseTo == 0 || baseTo > 256) {
		throw std::invalid_argument("Base must be between 1 and 256");
	}

	// Base 1 has no positional representation (repeated division by 1 never reaches zero).
	if (baseTo == 1) {
		throw std::invalid_argument("Base must be between 2 and 256");
	}

	// The input is parsed as hexadecimal; no other input base is implemented.
	if (baseFrom != 16) {
		throw std::invalid_argument("Only base 16 input is supported");
	}

	size_t symbol_table_len = strlen(baseToSymbolTable);
	if (symbol_table_len < baseTo) {
		throw std::invalid_argument("Symbol table too short for specified base");
	}

	// Validate hashHex contains only valid hex characters
	for (char c : hashHex) {
		if (!std::isxdigit(static_cast<unsigned char>(c))) {
			throw std::invalid_argument("Input contains non-hex character: " + std::string(1, c));
		}
	}

	try {
		// Skip leading zero digits; an all-zero input is the value zero, written as one zero symbol.
		const size_t first = hashHex.find_first_not_of('0');
		if (first == std::string::npos) {
			return std::string(1, baseToSymbolTable[0]);
		}

		// Pack the significant hex digits into big-endian 32-bit limbs (8 digits per limb).
		// The most significant limb takes the leading (len % 8) digits, or a full 8.
		const size_t digits = hashHex.size() - first;
		std::vector<uint32_t> limbs;
		limbs.reserve((digits + 7) / 8);
		size_t head = digits % 8;
		if (head == 0) {
			head = 8;
		}
		uint32_t limb = 0;
		size_t inLimb = 0;
		for (size_t i = first; i < hashHex.size(); ++i) {
			const unsigned char c = static_cast<unsigned char>(hashHex[i]);
			uint32_t nibble = 0;
			if (c >= '0' && c <= '9') {
				nibble = static_cast<uint32_t>(c - '0');
			} else if (c >= 'a' && c <= 'f') {
				nibble = static_cast<uint32_t>(c - 'a' + 10);
			} else {
				nibble = static_cast<uint32_t>(c - 'A' + 10);
			}
			limb = (limb << 4U) | nibble;
			++inLimb;
			if (inLimb == head) {
				limbs.push_back(limb);
				limb = 0;
				inLimb = 0;
				head = 8;
			}
		}

		// Repeated long division by baseTo; each remainder is the next least significant output digit.
		std::string res;
		res.reserve(digits * 2); // Reasonable estimate to avoid frequent reallocations
		std::vector<uint32_t> quotient;
		quotient.reserve(limbs.size());
		while (!limbs.empty()) {
			uint64_t rem = 0;
			quotient.clear();
			for (uint32_t l : limbs) {
				const uint64_t cur = (rem << 32U) | static_cast<uint64_t>(l);
				const auto q = static_cast<uint32_t>(cur / baseTo);
				rem = cur % baseTo;
				if (!quotient.empty() || q != 0) {
					quotient.push_back(q);
				}
			}
			res.push_back(baseToSymbolTable[static_cast<size_t>(rem)]);
			limbs.swap(quotient);
		}
		std::reverse(res.begin(), res.end());

		return res;
	} catch (const std::exception& e) {
		throw std::runtime_error("Base conversion failed: " + std::string(e.what()));
	}
}

std::string toHexString(const std::vector<unsigned char> &data)
{
	std::ostringstream out;
	out << std::hex << std::setfill('0');
	
	for (const auto& byte : data)
	{
		out << std::setw(2) << static_cast<unsigned int>(byte);
	}

	return out.str();
}

std::vector<unsigned char> fromHexString(const std::string &str)
{
	// Validate input string length is even
	if (str.size() % 2 != 0) {
		throw std::invalid_argument("Hex string must have even length");
	}

	std::vector<unsigned char> bytes;
	bytes.reserve(str.size() / 2);

	for (size_t i = 0; i < str.size(); i += 2)
	{
		// Validate we have at least 2 characters
		if (i + 1 >= str.size()) break;

		// Extract 2-character hex substring
		std::string hex_byte = str.substr(i, 2);
		
		// Validate hex characters
		for (char c : hex_byte) {
			if (!std::isxdigit(static_cast<unsigned char>(c))) {
				throw std::invalid_argument("Invalid hex character: " + std::string(1, c));
			}
		}

		// Safe conversion using strtoul with error checking
		char* end_ptr = nullptr;
		unsigned long value = std::strtoul(hex_byte.c_str(), &end_ptr, 16);
		
		// Check for conversion errors
		if (end_ptr != hex_byte.c_str() + 2 || value > 255) {
			throw std::invalid_argument("Invalid hex byte: " + hex_byte);
		}

		bytes.push_back(static_cast<unsigned char>(value));
	}

	return bytes;
}

std::vector<std::string> chunkSubstr(const std::string &str, size_t size)
{
	size_t numChunks = (size_t)std::ceil((double)str.length() / size);

	std::vector<std::string> chunks;
	chunks.reserve(numChunks);

	for (size_t i = 0, offset = 0; i < numChunks; i++, offset += size)
	{
		chunks.push_back(str.substr(offset, size));
	}

	return chunks;
}

/**
 * Generates a cryptographically-secure pseudo-random string of the given length out of the given alphabet
 *
 * @param length
 * @param alphabet
 * @returns {string}
 */
std::string randomString(size_t length, const char *alphabet)
{
	if (length == 0) {
		return std::string();
	}
	
	if (alphabet == nullptr) {
		throw std::invalid_argument("Alphabet cannot be null");
	}

	size_t alphabet_len = strlen(alphabet);
	if (alphabet_len == 0) {
		throw std::invalid_argument("Alphabet cannot be empty");
	}

	// Initialize libsodium if not already done
	if (sodium_init() < 0) {
		throw std::runtime_error("Failed to initialize libsodium");
	}

	std::string result;
	result.resize(length);

	// Generate cryptographically secure random bytes
	randombytes_buf(result.data(), result.size());

	// Map bytes to alphabet characters
	for (auto &byte : result)
	{
		byte = alphabet[static_cast<unsigned char>(byte) % alphabet_len];
	}

	return result;
}

std::vector<unsigned char> shake256(const std::string &str, size_t shake256_bits_size)
{
	// NOTE: empty input is valid — SHAKE256("") is a well-defined canonical value
	// (46b9dd2b…); FIPS202_SHAKE256(ptr, 0, …) computes it correctly. No empty-input
	// short-circuit here (it would diverge from JS/Python). No protocol caller hashes
	// an empty string, so this only affects the empty-input edge case.
	if (shake256_bits_size == 0 || shake256_bits_size % 8 != 0) {
		throw std::invalid_argument("SHAKE256 bits size must be positive and divisible by 8");
	}

	size_t output_bytes = shake256_bits_size / 8;
	std::vector<unsigned char> output(output_bytes);

	// Call SHAKE256 - this function doesn't return error codes
	FIPS202_SHAKE256(
		reinterpret_cast<const unsigned char*>(str.data()), 
		static_cast<int>(str.size()), 
		output.data(), 
		static_cast<int>(output.size())
	);

	// Note: FIPS202_SHAKE256 is a void function and doesn't return error codes
	
	return output;
}

std::string shake256Hex(const std::string &str, size_t shake256_size)
{
	return toHexString(shake256(str, shake256_size));
}

std::string toUtf8(const std::wstring &wstr)
{
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;

	return convert.to_bytes(wstr);
}

std::wstring fromUtf8(const std::string &str)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> wconverter;

	return wconverter.from_bytes(str);
}

// =============================================================================
// BASE64 UTILITIES (ML-KEM JavaScript Compatibility)
// =============================================================================

std::string toBase64(const std::vector<uint8_t> &data) {
    // Simple Base64 encoding implementation
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t value = 0;
        int count = 0;
        
        for (int j = 0; j < 3 && i + j < data.size(); ++j) {
            value = (value << 8) | data[i + j];
            ++count;
        }
        
        value <<= (3 - count) * 8;
        
        for (int j = 0; j < 4; ++j) {
            if (j <= count) {
                result += chars[(value >> (18 - j * 6)) & 0x3F];
            } else {
                result += '=';
            }
        }
    }
    
    return result;
}

std::vector<uint8_t> fromBase64(const std::string &str) {
    // Simple Base64 decoding implementation
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    
    std::vector<int> table(256, -1);
    for (size_t i = 0; i < chars.size(); ++i) {
        table[static_cast<unsigned char>(chars[i])] = static_cast<int>(i);
    }
    
    for (size_t i = 0; i < str.size(); i += 4) {
        uint32_t value = 0;
        int count = 0;
        
        for (int j = 0; j < 4 && i + j < str.size(); ++j) {
            if (str[i + j] != '=') {
                int index = table[static_cast<unsigned char>(str[i + j])];
                if (index == -1) continue;
                value = (value << 6) | index;
                ++count;
            }
        }
        
        value <<= (4 - count) * 6;
        
        for (int j = 0; j < count - 1; ++j) {
            result.push_back(static_cast<uint8_t>((value >> (16 - j * 8)) & 0xFF));
        }
    }
    
    return result;
}

// 2048-hex WOTS+ signature <-> 1368-char base64. Mirrors the JS reference
// (strings.js hexToBase64/base64ToHex), which is Buffer.from(hex,'hex').toString('base64')
// and its inverse. hexToBase64 throws std::invalid_argument on odd-length or non-hex input
// (via fromHexString); base64ToHex is lenient like Buffer.from(str,'base64') — it skips
// characters outside the alphabet — so callers must length-check the result.
std::string hexToBase64(const std::string &hex) { return toBase64(fromHexString(hex)); }

std::string base64ToHex(const std::string &b64) { return toHexString(fromBase64(b64)); }
