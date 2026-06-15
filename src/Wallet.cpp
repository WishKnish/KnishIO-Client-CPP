#include "Wallet.h"

#include "utility.h"
#include "crypto.h"
#include "crypto_bigint.h"
#include "third_party/BigInt/bigInt.h"
#include "third_party/nlohmann/json.hpp"
#include "KnishIOClient.h"
#include <sodium.h>

using json = nlohmann::json;

namespace KnishIO {

/**
   * @param {string} secret - typically a 2048-character biometric hash
   * @param {string} token - slug for the token this wallet is intended for
   * @param {string | null} position - hexadecimal string used to salt the secret and produce one-time signatures
   * @param {number} saltLength - length of the position parameter that should be generated if position is not provided
   */
Wallet::Wallet(const std::string &secret, const std::string &token, const std::string &position, size_t saltLength)
	: position(position)
	, token(token)
{
	// Position via which (combined with token) we will generate the one-time keys
	if (this->position.empty())
	{
		this->position = randomString(saltLength, "abcdef0123456789");
	}

	// Position via which (combined with token) we will generate the one-time keys
	this->key = Wallet::generateWalletKey(secret, this->token, this->position);

	this->address = Wallet::generateWalletAddress(this->key);
	this->bundle = generateBundleHash(secret);

	generatePublicAndPrivateKeys(this->privkey, this->pubkey);
	
	// Initialize ML-KEM768 keys for JavaScript compatibility
	initializeMLKEM();
}

Wallet::~Wallet()
{
	// SECURITY: Securely clear all cryptographic materials from memory
	if (!key.empty()) sodium_memzero(const_cast<char*>(key.data()), key.size());
	if (!address.empty()) sodium_memzero(const_cast<char*>(address.data()), address.size());
	if (!bundle.empty()) sodium_memzero(const_cast<char*>(bundle.data()), bundle.size());
	if (!position.empty()) sodium_memzero(const_cast<char*>(position.data()), position.size());
	if (!privkey.empty()) sodium_memzero(privkey.data(), privkey.size());
	if (!pubkey.empty()) sodium_memzero(pubkey.data(), pubkey.size());
	
	// SECURITY: Clear ML-KEM768 keys
	if (!mlkem_public_key.empty()) sodium_memzero(mlkem_public_key.data(), mlkem_public_key.size());
	if (!mlkem_private_key.empty()) sodium_memzero(mlkem_private_key.data(), mlkem_private_key.size());
}

bool Wallet::generateMyPublicAndPrivateKeys()
{
	return generatePublicAndPrivateKeys(this->privkey, this->pubkey);
}

/**
  * Uses the current wallet's private key to decrypt the given message
  *
  * @param {string} encryptedMessage hex string of encrypted data
  * @returns {string} decrypted message (in UTF8)
  */
std::string Wallet::decryptMyMessage(const std::string &encryptedMessage)
{
	try {
		std::string result = decryptMessage(encryptedMessage, this->pubkey, this->privkey);
		
		// Note: The actual decrypted message should not be cleared here as it's the return value
		// The calling code is responsible for securely handling the decrypted plaintext
		
		return result;
	} catch (const std::exception& e) {
		throw std::runtime_error("Message decryption failed: " + std::string(e.what()));
	}
}

/**
   * Hashes the user secret to produce a wallet bundle
   *
   * @param {string} secret
   * @returns {string}
   */
std::string Wallet::generateBundleHash(const std::string &secret)
{
	return shake256Hex(secret, 256);
}

/**
   *
   * @param {string} secret
   * @param {string} token
   * @param {string} position
   * @return {string}
   */
std::string Wallet::generateWalletKey(const std::string &secret, const std::string &token, const std::string &position)
{
	try {
		// SECURITY: Using constant-time BigInt operations to prevent timing attacks
		// This replaces the vulnerable BigInt::Rossi operations that could leak timing information
		
		// Validate inputs are valid hex strings
		if (!knishio::WalletCrypto::isValidHex(secret)) {
			throw std::invalid_argument("Secret must be a valid hexadecimal string");
		}
		if (!knishio::WalletCrypto::isValidHex(position)) {
			throw std::invalid_argument("Position must be a valid hexadecimal string");
		}
		
		// Constant-time addition of secret and position
		std::string indexedKeyHex = knishio::WalletCrypto::constantTimeHexAdd(secret, position);
		
		// Prepare intermediate key sponge
		std::string intermediateKeySponge;
		intermediateKeySponge.reserve(indexedKeyHex.length() + token.length());
		intermediateKeySponge.append(indexedKeyHex);

		if (!token.empty()) {
			intermediateKeySponge.append(token);
		}

		// Generate the private key using double SHAKE256 hashing
		std::string result = shake256Hex(shake256Hex(intermediateKeySponge, 8192), 8192);
		
		// Securely clear sensitive intermediate values
		if (!indexedKeyHex.empty()) {
			sodium_memzero(const_cast<char*>(indexedKeyHex.data()), indexedKeyHex.size());
		}
		if (!intermediateKeySponge.empty()) {
			sodium_memzero(const_cast<char*>(intermediateKeySponge.data()), intermediateKeySponge.size());
		}
		
		return result;
		
	} catch (const std::exception& e) {
		throw std::runtime_error("Wallet key generation failed: " + std::string(e.what()));
	}
}

/**
  * @param {string} key
  * @return {string}
  */
std::string Wallet::generateWalletAddress(const std::string &key)
{
	// Subdivide private key into 16 fragments of 128 characters each
	auto keyFragments = chunkSubstr(key, 128);

	// Generating wallet digest
	std::string digestSponge;

	for (auto &workingFragment : keyFragments)
	{
		for (int i = 1; i <= 16; i++)
		{
			workingFragment = shake256Hex(workingFragment, 512);
		}

		digestSponge += workingFragment;
	}

	// Producing wallet address
	return shake256Hex(shake256Hex(digestSponge, 8192), 256);
}

// =============================================================================
// ML-KEM768 POST-QUANTUM ENCRYPTION (JavaScript SDK Compatibility)
// =============================================================================

#ifdef HAVE_MLKEM_NATIVE
extern "C" {
    // mlkem-native configuration for ML-KEM768
    #define MLK_CONFIG_API_PARAMETER_SET 768
    #define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem
    #include "mlkem_native.h"
}
#endif

void Wallet::initializeMLKEM() {
#ifdef HAVE_MLKEM_NATIVE
    if (key.empty()) {
        return;
    }
    
    // Generate 64-byte seed from wallet key following JavaScript pattern exactly
    // JavaScript: const seedHex = generateSecret(this.key, 128) → 128 hex chars (64-byte d‖z seed)
    auto seed_hex = knishio::KnishIOClient::generateSecret(key, 128);  // 128 hex chars = 64 bytes

    // Convert hex to bytes — full 64-byte seed, matching JS/Python
    std::vector<uint8_t> seed_bytes(64);
    for (size_t i = 0; i < 64; i++) {
        if (i * 2 + 1 < seed_hex.length()) {
            std::string hex_pair = seed_hex.substr(i * 2, 2);
            seed_bytes[i] = static_cast<uint8_t>(std::stoul(hex_pair, nullptr, 16));
        }
    }
    
    // Resize vectors to correct ML-KEM768 sizes
    mlkem_public_key.resize(1184);   // MLKEM768_PUBLICKEYBYTES
    mlkem_private_key.resize(2400);  // MLKEM768_SECRETKEYBYTES
    
    // Generate deterministic ML-KEM768 keys using mlkem-native
    int result = crypto_kem_keypair_derand(
        mlkem_public_key.data(),
        mlkem_private_key.data(),
        seed_bytes.data()
    );
    
    if (result != 0) {
        throw std::runtime_error("Failed to generate ML-KEM768 keys");
    }
    
    // Update pubkey to ML-KEM768 public key (Base64 encoded like JavaScript)
    pubkey = mlkem_public_key;  // Store raw bytes
    
    // Securely clear seed
    sodium_memzero(seed_bytes.data(), seed_bytes.size());
#endif
}

// AES-256-GCM encryption helper (matches C SDK implementation)
// Format: [IV (12 bytes)][ciphertext][authentication tag (16 bytes)]
std::vector<uint8_t> Wallet::encryptWithSharedSecret(const std::vector<uint8_t>& message, const std::vector<uint8_t>& shared_secret) {
    if (shared_secret.size() != 32) {
        throw std::invalid_argument("Shared secret must be 32 bytes for AES-256-GCM");
    }

    // Initialize AES-256-GCM
    if (crypto_aead_aes256gcm_is_available() == 0) {
        throw std::runtime_error("AES-256-GCM not available on this platform");
    }

    // Generate random 12-byte IV (nonce)
    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;
    std::vector<uint8_t> iv(IV_SIZE);
    randombytes_buf(iv.data(), IV_SIZE);

    // Prepare output buffer: [IV (12)][ciphertext][tag (16)]
    std::vector<uint8_t> output(IV_SIZE + message.size() + TAG_SIZE);

    // Copy IV to beginning of output
    std::copy(iv.begin(), iv.end(), output.begin());

    // Encrypt message with AES-256-GCM
    unsigned long long ciphertext_len;
    int result = crypto_aead_aes256gcm_encrypt(
        output.data() + IV_SIZE,           // ciphertext destination
        &ciphertext_len,                   // ciphertext length output
        message.data(),                    // plaintext
        message.size(),                    // plaintext length
        nullptr,                           // additional data (none)
        0,                                 // additional data length
        nullptr,                           // secret nonce (unused)
        iv.data(),                         // public nonce (IV)
        shared_secret.data()               // 32-byte key
    );

    if (result != 0) {
        throw std::runtime_error("AES-256-GCM encryption failed");
    }

    // Resize output to actual length (should be IV_SIZE + ciphertext_len which includes tag)
    output.resize(IV_SIZE + ciphertext_len);

    return output;
}

// AES-256-GCM decryption helper (matches C SDK implementation)
// Format: [IV (12 bytes)][ciphertext][authentication tag (16 bytes)]
std::vector<uint8_t> Wallet::decryptWithSharedSecret(const std::vector<uint8_t>& encrypted_message, const std::vector<uint8_t>& shared_secret) {
    if (shared_secret.size() != 32) {
        throw std::invalid_argument("Shared secret must be 32 bytes for AES-256-GCM");
    }

    // Initialize AES-256-GCM
    if (crypto_aead_aes256gcm_is_available() == 0) {
        throw std::runtime_error("AES-256-GCM not available on this platform");
    }

    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    // Minimum size check: IV + tag (at least 28 bytes)
    if (encrypted_message.size() < IV_SIZE + TAG_SIZE) {
        throw std::invalid_argument("Encrypted message too short for AES-256-GCM format");
    }

    // Extract IV from beginning
    const uint8_t* iv = encrypted_message.data();

    // Extract ciphertext + tag (everything after IV)
    const uint8_t* ciphertext_with_tag = encrypted_message.data() + IV_SIZE;
    size_t ciphertext_with_tag_len = encrypted_message.size() - IV_SIZE;

    // Prepare output buffer for plaintext
    std::vector<uint8_t> plaintext(ciphertext_with_tag_len);
    unsigned long long plaintext_len;

    // Decrypt message with AES-256-GCM (automatically verifies authentication tag)
    int result = crypto_aead_aes256gcm_decrypt(
        plaintext.data(),                  // plaintext destination
        &plaintext_len,                    // plaintext length output
        nullptr,                           // secret nonce (unused)
        ciphertext_with_tag,               // ciphertext + tag
        ciphertext_with_tag_len,           // ciphertext + tag length
        nullptr,                           // additional data (none)
        0,                                 // additional data length
        iv,                                // public nonce (IV)
        shared_secret.data()               // 32-byte key
    );

    if (result != 0) {
        throw std::runtime_error("AES-256-GCM decryption failed: authentication tag mismatch");
    }

    // Resize to actual plaintext length
    plaintext.resize(plaintext_len);

    return plaintext;
}

std::map<std::string, std::string> Wallet::encryptMessageML768(const std::string& message, const std::string& recipient_pubkey) {
#ifdef HAVE_MLKEM_NATIVE
    // Decode recipient public key from Base64
    auto recipient_key_bytes = fromBase64(recipient_pubkey);
    if (recipient_key_bytes.size() != 1184) {  // MLKEM768_PUBLICKEYBYTES
        throw std::invalid_argument("Invalid ML-KEM768 public key size");
    }
    
    // Encapsulate to generate shared secret and ciphertext
    std::vector<uint8_t> ciphertext(1088);      // MLKEM768_CIPHERTEXTBYTES
    std::vector<uint8_t> shared_secret(32);     // MLKEM768_SHAREDSECRETBYTES
    
    int result = crypto_kem_enc(
        ciphertext.data(),
        shared_secret.data(), 
        recipient_key_bytes.data()
    );
    
    if (result != 0) {
        throw std::runtime_error("ML-KEM768 encapsulation failed");
    }

    // JSON-encode message (cross-SDK compatibility requirement)
    // Other SDKs (PHP, JavaScript, Kotlin) JSON-encode messages before encryption
    json message_json = message;
    std::string message_json_str = message_json.dump();

    // Encrypt JSON-encoded message with shared secret using AES-256-GCM
    std::vector<uint8_t> message_bytes(message_json_str.begin(), message_json_str.end());
    std::vector<uint8_t> encrypted_bytes = encryptWithSharedSecret(message_bytes, shared_secret);
    std::string encrypted_message = toBase64(encrypted_bytes);

    // Clear shared secret and sensitive data
    sodium_memzero(shared_secret.data(), shared_secret.size());
    sodium_memzero(message_bytes.data(), message_bytes.size());
    sodium_memzero(encrypted_bytes.data(), encrypted_bytes.size());

    return {
        {"cipherText", toBase64(ciphertext)},
        {"encryptedMessage", encrypted_message}
    };
#else
    throw std::runtime_error("ML-KEM768 not available");
#endif
}

std::string Wallet::decryptMessageML768(const std::map<std::string, std::string>& encrypted_data) {
#ifdef HAVE_MLKEM_NATIVE
    auto ciphertext = fromBase64(encrypted_data.at("cipherText"));
    auto encrypted_message = fromBase64(encrypted_data.at("encryptedMessage"));
    
    if (ciphertext.size() != 1088) {  // MLKEM768_CIPHERTEXTBYTES
        throw std::invalid_argument("Invalid ML-KEM768 ciphertext size");
    }
    
    // Decapsulate to recover shared secret
    std::vector<uint8_t> shared_secret(32);  // MLKEM768_SHAREDSECRETBYTES
    
    int result = crypto_kem_dec(
        shared_secret.data(),
        ciphertext.data(),
        mlkem_private_key.data()
    );
    
    if (result != 0) {
        sodium_memzero(shared_secret.data(), shared_secret.size());
        throw std::runtime_error("ML-KEM768 decapsulation failed");
    }

    // Decrypt message with shared secret using AES-256-GCM
    std::vector<uint8_t> plaintext_bytes;
    try {
        plaintext_bytes = decryptWithSharedSecret(encrypted_message, shared_secret);
    } catch (const std::exception& e) {
        // Clear shared secret on failure
        sodium_memzero(shared_secret.data(), shared_secret.size());
        throw;
    }

    // Convert decrypted bytes to JSON string
    std::string plaintext_json(plaintext_bytes.begin(), plaintext_bytes.end());

    // JSON-decode the decrypted message (cross-SDK compatibility requirement)
    // Other SDKs (PHP, JavaScript, Kotlin) JSON-encode before encryption
    std::string plaintext;
    try {
        json parsed = json::parse(plaintext_json);
        plaintext = parsed.get<std::string>();
    } catch (const std::exception& e) {
        // If JSON parsing fails, return raw plaintext (backward compatibility)
        plaintext = plaintext_json;
    }

    // Clear shared secret and sensitive data
    sodium_memzero(shared_secret.data(), shared_secret.size());
    sodium_memzero(plaintext_bytes.data(), plaintext_bytes.size());

    return plaintext;
#else
    throw std::runtime_error("ML-KEM768 not available");
#endif
}

} // namespace KnishIO
