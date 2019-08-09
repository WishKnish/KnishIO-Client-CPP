#pragma once

#include <string>
#include <vector>

std::string charsetBaseConvert(const std::string &hashHex, unsigned int baseFrom, unsigned int baseTo, const char *baseToSymbolTable);
std::string toHexString(const std::vector<unsigned char> &data);

std::vector<std::string> chunkSubstr(const std::string &str, size_t size);
std::string randomString(size_t length = 256, const char *alphabet = "abcdef0123456789");

std::vector<unsigned char> shake256(const std::string &str, size_t shake256_size);
std::string shake256Hex(const std::string &str, size_t shake256_bits_size);
