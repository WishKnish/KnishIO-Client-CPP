#include "Wallet.h"

#include "utility.h"
#include "crypto.h"
#include "crypto_bigint.h"
#include "third_party/BigInt/bigInt.h"
#include "third_party/nlohmann/json.hpp"
#include "KnishIOClient.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

// AES-256-GCM encryption helper (OpenSSL EVP — portable, no AES-NI gate; mirrors C's aes_gcm.c)
// Format: [IV (12 bytes)][ciphertext][authentication tag (16 bytes)]
std::vector<uint8_t> Wallet::encryptWithSharedSecret(const std::vector<uint8_t>& message, const std::vector<uint8_t>& shared_secret) {
    if (shared_secret.size() != 32) {
        throw std::invalid_argument("Shared secret must be 32 bytes for AES-256-GCM");
    }

    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    // Generate random 12-byte IV (nonce) via OpenSSL CSPRNG
    std::vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), static_cast<int>(IV_SIZE)) != 1) {
        throw std::runtime_error("AES-256-GCM: IV generation failed");
    }

    // Prepare output buffer: [IV (12)][ciphertext][tag (16)]
    std::vector<uint8_t> output(IV_SIZE + message.size() + TAG_SIZE);
    std::copy(iv.begin(), iv.end(), output.begin());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("AES-256-GCM: failed to allocate cipher context");
    }

    int len = 0;
    int ciphertext_len = 0;
    bool ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_SIZE), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, shared_secret.data(), iv.data()) == 1 &&
        EVP_EncryptUpdate(ctx, output.data() + IV_SIZE, &len, message.data(), static_cast<int>(message.size())) == 1;
    if (ok) {
        ciphertext_len = len;
        ok = EVP_EncryptFinal_ex(ctx, output.data() + IV_SIZE + ciphertext_len, &len) == 1;
        ciphertext_len += len;
    }
    if (ok) {
        // Append the 16-byte authentication tag after the ciphertext
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_SIZE),
                                 output.data() + IV_SIZE + ciphertext_len) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("AES-256-GCM encryption failed");
    }

    // Final layout: [IV (12)][ciphertext][tag (16)]
    output.resize(IV_SIZE + static_cast<size_t>(ciphertext_len) + TAG_SIZE);
    return output;
}

// AES-256-GCM decryption helper (OpenSSL EVP — portable, no AES-NI gate; mirrors C's aes_gcm.c)
// Format: [IV (12 bytes)][ciphertext][authentication tag (16 bytes)]
std::vector<uint8_t> Wallet::decryptWithSharedSecret(const std::vector<uint8_t>& encrypted_message, const std::vector<uint8_t>& shared_secret) {
    if (shared_secret.size() != 32) {
        throw std::invalid_argument("Shared secret must be 32 bytes for AES-256-GCM");
    }

    constexpr size_t IV_SIZE = 12;
    constexpr size_t TAG_SIZE = 16;

    // Minimum size check: IV + tag (at least 28 bytes)
    if (encrypted_message.size() < IV_SIZE + TAG_SIZE) {
        throw std::invalid_argument("Encrypted message too short for AES-256-GCM format");
    }

    // Split [IV (12)][ciphertext][tag (16)]
    const uint8_t* iv = encrypted_message.data();
    const uint8_t* ciphertext = encrypted_message.data() + IV_SIZE;
    const size_t ciphertext_len = encrypted_message.size() - IV_SIZE - TAG_SIZE;
    const uint8_t* tag = encrypted_message.data() + encrypted_message.size() - TAG_SIZE;

    std::vector<uint8_t> plaintext(ciphertext_len);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("AES-256-GCM: failed to allocate cipher context");
    }

    int len = 0;
    int plaintext_len = 0;
    int ret = 0;
    bool ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(IV_SIZE), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, shared_secret.data(), iv) == 1 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, static_cast<int>(ciphertext_len)) == 1;
    if (ok) {
        plaintext_len = len;
        // Set the expected authentication tag, then finalize (verifies the tag)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(TAG_SIZE),
                                 const_cast<uint8_t*>(tag)) == 1;
    }
    if (ok) {
        ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok || ret <= 0) {
        throw std::runtime_error("AES-256-GCM decryption failed: authentication tag mismatch");
    }

    plaintext_len += len;
    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
}

std::map<std::string, std::string> Wallet::encryptMessageML768(const std::string& message, const std::string& recipient_pubkey) {
#ifdef HAVE_MLKEM_NATIVE
    // Decode recipient public key from Base64
    auto recipient_key_bytes = fromBase64(recipient_pubkey);
    if (recipient_key_bytes.size() != 1184) {  // MLKEM768_PUBLICKEYBYTES
        // A wrong-length key here almost always means the node did not advertise an ML-KEM public key
        // in its auth `key` field (e.g. a validator predating the PQ-transport build) — give an
        // actionable message, consistent with the other SDKs' encrypt guards.
        throw std::invalid_argument(
            "KnishIO: cannot ML-KEM-encrypt — recipient public key is " +
            std::to_string(recipient_key_bytes.size()) +
            " bytes, expected 1184 (ML-KEM-768). The node likely did not advertise an ML-KEM public key "
            "(upgrade the validator to a PQ-transport build), or authenticate with encrypt=false.");
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

// ML-KEM768 decapsulate + AES-256-GCM decrypt → the RAW decrypted UTF-8 string (no JSON-decode).
// Shared by decryptMessageML768 (which JSON-decodes the result — the c136 vector + the PQ-transport
// REQUEST direction encrypt a JSON string value) and decryptMyMessageML768 (the PQ-transport
// RESPONSE direction, where the validator encrypts the response OBJECT → the raw plaintext is the
// inner GraphQL response JSON directly). PQ-transport Phase E.
std::string Wallet::mlkemDecryptToString(const std::map<std::string, std::string>& encrypted_data) {
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

    // Convert decrypted bytes to the raw plaintext string
    std::string plaintext_json(plaintext_bytes.begin(), plaintext_bytes.end());

    // Clear shared secret and sensitive data
    sodium_memzero(shared_secret.data(), shared_secret.size());
    sodium_memzero(plaintext_bytes.data(), plaintext_bytes.size());

    return plaintext_json;
#else
    throw std::runtime_error("ML-KEM768 not available");
#endif
}

std::string Wallet::decryptMessageML768(const std::map<std::string, std::string>& encrypted_data) {
    // JSON-decode the raw decrypted plaintext (cross-SDK compatibility: the c136 vector + the
    // request direction encrypt a JSON *string* value). The PQ-transport RESPONSE path is an
    // OBJECT and uses the raw helper directly (decryptMyMessageML768).
    std::string plaintext_json = mlkemDecryptToString(encrypted_data);
    try {
        json parsed = json::parse(plaintext_json);
        return parsed.get<std::string>();
    } catch (const std::exception& e) {
        // If JSON parsing fails / isn't a string, return raw plaintext (backward compatibility)
        return plaintext_json;
    }
}

// Canonical cross-SDK hashShare for a public key: standard base64 of SHAKE256(pubkey_utf8, 8 bytes)
// — byte-matches the validator's hash_share and the JS/Kotlin/PHP/TS/Python hashShare. NOTE
// shake256() takes a BIT length, so 64 bits = 8 bytes. PQ-transport Phase E.
std::string Wallet::hashShare(const std::string& pubkeyStr) {
    return toBase64(shake256(pubkeyStr, 64));
}

// Post-quantum (ML-KEM768) CipherHash request envelope: a stringified single-recipient map
// { "<hashShare(recipient_pubkey)>": {cipherText, encryptedMessage} }. Matches the Rust validator's
// CipherHash handler. PQ-transport Phase E.
std::string Wallet::encryptStringML768(const std::string& message, const std::string& recipient_pubkey) {
    auto envelope = encryptMessageML768(message, recipient_pubkey);
    json map;
    map[hashShare(recipient_pubkey)] = envelope;  // map<string,string> → JSON object
    return map.dump();
}

// Decrypt a CipherHash response map (stringified) addressed to THIS wallet's ML-KEM pubkey
// (hashShare(base64(mlkem_public_key))) → the RAW inner GraphQL response JSON (NOT json-decoded;
// it replaces the HTTP response body). Empty string if no entry. PQ-transport Phase E.
std::string Wallet::decryptMyMessageML768(const std::string& mapJson) {
    json map = json::parse(mapJson);
    std::string shareKey = hashShare(toBase64(mlkem_public_key));
    if (!map.contains(shareKey)) {
        return std::string();
    }
    auto envelope = map.at(shareKey).get<std::map<std::string, std::string>>();
    return mlkemDecryptToString(envelope);
}

// Partition this wallet's tokenUnits across the SENT set (id in `units`) and the KEPT set,
// mirroring the JS/Rust/Python/C SDK split. Value semantics (no manual ownership): the SENT
// units stay on this wallet and are copied to recipientWallet (if non-null); the KEPT units
// go to remainderWallet. For a burn, recipientWallet is null (the burned units stay here).
void Wallet::splitUnits(const std::vector<std::string> &units, Wallet &remainderWallet, Wallet *recipientWallet)
{
    if (units.empty()) {
        return;
    }
    std::vector<TokenUnit> sent;
    std::vector<TokenUnit> kept;
    for (const auto &tu : this->tokenUnits) {
        bool inUnits = false;
        for (const auto &u : units) {
            if (tu.id == u) { inUnits = true; break; }
        }
        if (inUnits) {
            sent.push_back(tu);
        } else {
            kept.push_back(tu);
        }
    }
    this->tokenUnits = sent;
    if (recipientWallet != nullptr) {
        recipientWallet->tokenUnits = sent;
    }
    remainderWallet.tokenUnits = kept;
}

void Wallet::splitUnitsMulti(const std::vector<std::vector<std::string>> &recipientUnitLists,
                             std::vector<Wallet> &recipientWallets, Wallet &remainderWallet)
{
    // Any units to send? (else fungible -> no-op)
    bool anySent = false;
    for (const auto &lst : recipientUnitLists) {
        if (!lst.empty()) { anySent = true; break; }
    }
    if (!anySent) {
        return;
    }

    auto idInList = [](const std::string &id, const std::vector<std::string> &lst) {
        for (const auto &u : lst) {
            if (u == id) { return true; }
        }
        return false;
    };

    // Each recipient gets its own subset of the source's units
    for (size_t i = 0; i < recipientWallets.size(); ++i) {
        std::vector<TokenUnit> subset;
        const std::vector<std::string> &ids = i < recipientUnitLists.size() ? recipientUnitLists[i] : std::vector<std::string>{};
        for (const auto &tu : this->tokenUnits) {
            if (idInList(tu.id, ids)) { subset.push_back(tu); }
        }
        recipientWallets[i].tokenUnits = subset;
    }

    // Remainder keeps the KEPT units (∉ any list); source carries the SENT union (∈ some list)
    std::vector<TokenUnit> kept;
    std::vector<TokenUnit> sentUnion;
    for (const auto &tu : this->tokenUnits) {
        bool sent = false;
        for (const auto &lst : recipientUnitLists) {
            if (idInList(tu.id, lst)) { sent = true; break; }
        }
        if (sent) { sentUnion.push_back(tu); } else { kept.push_back(tu); }
    }
    remainderWallet.tokenUnits = kept;
    this->tokenUnits = sentUnion;
}

// Serialize this wallet's tokenUnits to the canonical cross-SDK wire value `[[id, name, metas], ...]`
// (matches JS/Rust/Python/C). Returns "[]" when there are no units.
std::string Wallet::getTokenUnitsJson() const
{
    nlohmann::json arr = nlohmann::json::array();
    for (const auto &tu : this->tokenUnits) {
        nlohmann::json metas = nlohmann::json::object();
        for (const auto &kv : tu.metas) {
            metas[kv.first] = kv.second;
        }
        nlohmann::json inner = nlohmann::json::array();
        inner.push_back(tu.id);
        inner.push_back(tu.name);
        inner.push_back(metas);
        arr.push_back(inner);
    }
    return arr.dump();
}

} // namespace KnishIO
