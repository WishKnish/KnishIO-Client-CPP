#include "utility.h"

#include "third_party/BigInt/bigInt.h"
#include "third_party/Keccak/Keccak.h"

#include <random>
#include <codecvt>

std::string charsetBaseConvert(const std::string &hashHex, unsigned int baseFrom, unsigned int baseTo, const char *baseToSymbolTable)
{
	if (hashHex.empty()
		|| baseToSymbolTable == nullptr || strlen(baseToSymbolTable) < baseTo)
	{
		return std::string();
	}

	BigInt::Rossi val(hashHex, BigInt::HEX_DIGIT);

	std::string res;
	BigInt::Rossi rem;

	do
	{
		val = val.divide(val, BigInt::Rossi(baseTo), &rem);

		int remInt = strtol(rem.toStrDec().c_str(), nullptr, 10);

		res.insert(res.begin(), baseToSymbolTable[remInt]);
	} while (val != BigInt::Rossi(0));

	return res;
}

std::string toHexString(const std::vector<unsigned char> &data)
{
	std::string out;
	out.reserve(data.size() * 2);

	for (auto &byte : data)
	{
		char s[16];
		sprintf_s(s, "%02x", byte);

		out.append(s);
	}

	return out;
}

std::vector<unsigned char> fromHexString(const std::string &str)
{
	std::vector<unsigned char> bytes;
	bytes.reserve(str.size() / 2);

	for (size_t i = 0; i < str.size(); i += 2)
	{
		if (i + 1 >= str.size()) break;

		unsigned int byte;
		sscanf_s(&str[i], "%02x", &byte);

		bytes.push_back(byte);
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
	if (alphabet == nullptr) return std::string();

	// TODO: need crypto random numbers
	thread_local std::mt19937 randomGen(std::random_device{}()); // seed by random device

	std::string out;
	out.reserve(length);

	for (size_t i = 0; i < length; i++)
	{
		unsigned int randomValue = randomGen();
		out.push_back(alphabet[randomValue % strlen(alphabet)]);
	}

	return out;
}

std::vector<unsigned char> shake256(const std::string &str, size_t shake256_bits_size)
{
	std::vector<unsigned char> output;

	if (str.empty()) return output;
	
	output.resize(shake256_bits_size / 8);

	FIPS202_SHAKE256(reinterpret_cast<const unsigned char*>(str.data()), (int)str.size(), output.data(), (int)output.size());

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
