#pragma once

#include <string>
#include <vector>
#include <cstdint>  // uint8_t in the declarations below — not transitively included on Linux (cycle 127)

std::string charsetBaseConvert(const std::string &hashHex, unsigned int baseFrom, unsigned int baseTo, const char *baseToSymbolTable);

std::string toHexString(const std::vector<unsigned char> &data);
std::vector<unsigned char> fromHexString(const std::string &str);

std::string toBase64(const std::vector<uint8_t> &data);
std::vector<uint8_t> fromBase64(const std::string &str);

// 2048-hex WOTS+ signature <-> 1368-char base64 (RFC 4648 standard alphabet, '=' padding).
// Composed from fromHexString/toBase64 and fromBase64/toHexString; adds no new encoder.
std::string hexToBase64(const std::string &hex);
std::string base64ToHex(const std::string &b64);

std::vector<std::string> chunkSubstr(const std::string &str, size_t size);
std::string randomString(size_t length = 256, const char *alphabet = "abcdef0123456789");

std::vector<unsigned char> shake256(const std::string &str, size_t shake256_size);
std::string shake256Hex(const std::string &str, size_t shake256_bits_size);

std::string toUtf8(const std::wstring &wstr);
std::wstring fromUtf8(const std::string &str);
