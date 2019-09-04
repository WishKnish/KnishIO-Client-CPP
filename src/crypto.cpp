#include "crypto.h"

#include <sodium.h>
#include "utility.h"

/**
 * Encrypts the given message or data with the recipient's public key
 *
 * @param messageUtf8 message encoded in UTF8
 * @param recipientPublicKey
 * @returns hex string of encrypted data
 */
std::string encryptMessage(const std::string &messageUtf8, const std::vector<unsigned char> &recipientPublicKey)
{
	if (messageUtf8.empty())
	{
		return std::string();
	}

	if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES)
	{
		throw std::exception("wrong public key size");
	}

	std::vector<unsigned char> encrypted;
	encrypted.resize(crypto_box_SEALBYTES + messageUtf8.size());

	if (crypto_box_seal(encrypted.data(), (const unsigned char*)messageUtf8.data(), (long long)messageUtf8.size(), recipientPublicKey.data()) != 0)
	{
		return std::string();
	}

	return toHexString(encrypted);
}

/**
 * Uses the given private key to decrypt an encrypted message
 *
 * @param {string} encryptedMessage hex string of encrypted data
 * @param {vector} recipientPublicKey
 * @param {vector} recipientPrivateKey
 * @returns {string} decrypted message encoded in UTF8
 */
std::string decryptMessage(const std::string &encryptedMessage, const std::vector<unsigned char> &recipientPublicKey, const std::vector<unsigned char> &recipientPrivateKey)
{
	if (encryptedMessage.empty())
	{
		return std::string();
	}

	if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES)
	{
		throw std::exception("wrong public key size");
	}

	if (recipientPrivateKey.size() != crypto_box_SECRETKEYBYTES)
	{
		throw std::exception("wrong secret key size");
	}

	std::vector<unsigned char> encryptedBytes = fromHexString(encryptedMessage);

	if (encryptedBytes.size() < crypto_box_SEALBYTES)
	{
		throw std::exception("wrong encrypted message size");
	}

	if (encryptedBytes.size() == crypto_box_SEALBYTES)
	{
		return std::string();
	}

	std::vector<unsigned char> decrypted;
	decrypted.resize(encryptedBytes.size() - crypto_box_SEALBYTES);

	if (crypto_box_seal_open(decrypted.data(), encryptedBytes.data(), (long long)encryptedBytes.size(), recipientPublicKey.data(), recipientPrivateKey.data()) != 0)
	{
		return std::string();
	}

	return std::string(decrypted.begin(), decrypted.end());
}

/**
 * Generates public and private key pair
 *
 * @param publicKey public key
 * @param privateKey private key
 * @returns success
 */
bool generatePublicAndPrivateKeys(std::vector<unsigned char> &publicKey, std::vector<unsigned char> &privateKey)
{
	publicKey.resize(crypto_box_PUBLICKEYBYTES);
	privateKey.resize(crypto_box_SECRETKEYBYTES);

	return (crypto_box_keypair(publicKey.data(), privateKey.data()) == 0);
}
