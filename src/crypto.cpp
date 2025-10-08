#include "crypto.h"

#include <sodium.h>
#include <stdexcept>
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
	// Initialize libsodium if not already done
	if (sodium_init() < 0) {
		throw std::runtime_error("Failed to initialize libsodium");
	}

	if (messageUtf8.empty()) {
		return std::string();
	}

	if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES) {
		throw std::invalid_argument("Invalid public key size. Expected " + 
			std::to_string(crypto_box_PUBLICKEYBYTES) + " bytes");
	}

	try {
		std::vector<unsigned char> encrypted;
		encrypted.resize(crypto_box_SEALBYTES + messageUtf8.size());

		int result = crypto_box_seal(
			encrypted.data(), 
			reinterpret_cast<const unsigned char*>(messageUtf8.data()), 
			messageUtf8.size(), 
			recipientPublicKey.data()
		);

		if (result != 0) {
			// Securely clear the encrypted buffer before throwing
			sodium_memzero(encrypted.data(), encrypted.size());
			throw std::runtime_error("Encryption failed");
		}

		std::string result_hex = toHexString(encrypted);
		
		// Securely clear the intermediate encrypted buffer
		sodium_memzero(encrypted.data(), encrypted.size());
		
		return result_hex;
		
	} catch (const std::exception& e) {
		throw std::runtime_error("Message encryption failed: " + std::string(e.what()));
	}
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
	// Initialize libsodium if not already done
	if (sodium_init() < 0) {
		throw std::runtime_error("Failed to initialize libsodium");
	}

	if (encryptedMessage.empty()) {
		return std::string();
	}

	if (recipientPublicKey.size() != crypto_box_PUBLICKEYBYTES) {
		throw std::invalid_argument("Invalid public key size. Expected " + 
			std::to_string(crypto_box_PUBLICKEYBYTES) + " bytes");
	}

	if (recipientPrivateKey.size() != crypto_box_SECRETKEYBYTES) {
		throw std::invalid_argument("Invalid private key size. Expected " + 
			std::to_string(crypto_box_SECRETKEYBYTES) + " bytes");
	}

	std::vector<unsigned char> encryptedBytes;
	std::vector<unsigned char> decrypted;

	try {
		encryptedBytes = fromHexString(encryptedMessage);

		if (encryptedBytes.size() < crypto_box_SEALBYTES) {
			throw std::invalid_argument("Encrypted message too short. Minimum size: " + 
				std::to_string(crypto_box_SEALBYTES) + " bytes");
		}

		if (encryptedBytes.size() == crypto_box_SEALBYTES) {
			// Securely clear intermediate data
			sodium_memzero(encryptedBytes.data(), encryptedBytes.size());
			return std::string();
		}

		decrypted.resize(encryptedBytes.size() - crypto_box_SEALBYTES);

		int result = crypto_box_seal_open(
			decrypted.data(), 
			encryptedBytes.data(), 
			encryptedBytes.size(), 
			recipientPublicKey.data(), 
			recipientPrivateKey.data()
		);

		if (result != 0) {
			// Securely clear sensitive data before throwing
			sodium_memzero(encryptedBytes.data(), encryptedBytes.size());
			sodium_memzero(decrypted.data(), decrypted.size());
			throw std::runtime_error("Decryption failed - invalid ciphertext or keys");
		}

		std::string result_str(decrypted.begin(), decrypted.end());
		
		// Securely clear intermediate buffers
		sodium_memzero(encryptedBytes.data(), encryptedBytes.size());
		sodium_memzero(decrypted.data(), decrypted.size());
		
		return result_str;
		
	} catch (const std::exception& e) {
		// Ensure cleanup even on exception
		if (!encryptedBytes.empty()) {
			sodium_memzero(encryptedBytes.data(), encryptedBytes.size());
		}
		if (!decrypted.empty()) {
			sodium_memzero(decrypted.data(), decrypted.size());
		}
		throw std::runtime_error("Message decryption failed: " + std::string(e.what()));
	}
}

/**
 * Generates public and private key pair
 *
 * @param publicKey public key (output parameter)
 * @param privateKey private key (output parameter)  
 * @returns success
 */
bool generatePublicAndPrivateKeys(std::vector<unsigned char> &publicKey, std::vector<unsigned char> &privateKey)
{
	try {
		// Initialize libsodium if not already done
		if (sodium_init() < 0) {
			throw std::runtime_error("Failed to initialize libsodium");
		}

		// Securely clear any existing key data
		if (!publicKey.empty()) {
			sodium_memzero(publicKey.data(), publicKey.size());
		}
		if (!privateKey.empty()) {
			sodium_memzero(privateKey.data(), privateKey.size());
		}

		// Resize vectors to correct key sizes
		publicKey.resize(crypto_box_PUBLICKEYBYTES);
		privateKey.resize(crypto_box_SECRETKEYBYTES);

		// Generate the key pair
		int result = crypto_box_keypair(publicKey.data(), privateKey.data());

		if (result != 0) {
			// Clear potentially partially written keys on failure
			sodium_memzero(publicKey.data(), publicKey.size());
			sodium_memzero(privateKey.data(), privateKey.size());
			return false;
		}

		return true;

	} catch (const std::exception&) {
		// Ensure keys are cleared on any exception
		if (!publicKey.empty()) {
			sodium_memzero(publicKey.data(), publicKey.size());
		}
		if (!privateKey.empty()) {
			sodium_memzero(privateKey.data(), privateKey.size());
		}
		return false;
	}
}
