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
Wallet::Wallet(const std::string &secret, const std::string &token, const std::string &position, size_t saltLength, int mlkemParameterSet)
	: position(position)
	, token(token)
	, mlkem_parameter_set(mlkemParameterSet)
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
	
	// Initialize ML-KEM keys
	initializeMLKEM(this->mlkem_parameter_set);
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
	
	// SECURITY: Clear ML-KEM keys
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
// ML-KEM POST-QUANTUM ENCRYPTION (JavaScript SDK Compatibility)
// =============================================================================

#ifdef HAVE_MLKEM_NATIVE
extern "C" {
    #define MLK_CONFIG_API_NO_SUPERCOP
    #define MLK_CONFIG_API_NO_RANDOMIZED_API

    #define MLK_CONFIG_API_PARAMETER_SET 768
    #define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem768
    #include "mlkem_native.h"
    #undef MLK_CONFIG_API_PARAMETER_SET
    #undef MLK_CONFIG_API_NAMESPACE_PREFIX
    #undef MLK_H

    #define MLK_CONFIG_API_NO_SUPERCOP
    #define MLK_CONFIG_API_NO_RANDOMIZED_API
    #define MLK_CONFIG_API_PARAMETER_SET 1024
    #define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem1024
    #include "mlkem_native.h"
    #undef MLK_CONFIG_API_PARAMETER_SET
    #undef MLK_CONFIG_API_NAMESPACE_PREFIX
    #undef MLK_H
}
#endif

Wallet::MlKemIdentity::~MlKemIdentity()
{
    if (!privateKey.empty()) {
        sodium_memzero(privateKey.data(), privateKey.size());
    }
}

// Derive an ML-KEM keypair at an arbitrary parameter set from this wallet's key. The 64-byte
// d‖z seed generateSecret(key, 128) produces takes NO parameter-set input — only the final
// keypair_derand call differs — so a KnishIO wallet can materialise both its ML-KEM-768 and its
// ML-KEM-1024 identity from key material it already holds. Does not mutate the wallet, and the
// returned private key is zeroized when the value leaves the caller's scope.
Wallet::MlKemIdentity Wallet::deriveMlKemKeypair(int parameterSet) const {
#ifdef HAVE_MLKEM_NATIVE
    if (parameterSet != 768 && parameterSet != 1024) {
        throw std::invalid_argument(
            "KnishIO: unsupported ML-KEM parameter set " + std::to_string(parameterSet) +
            "; expected 1024 or 768.");
    }

    MlKemIdentity identity;
    identity.parameterSet = parameterSet;

    if (key.empty()) {
        return identity;
    }

    // Generate 64-byte seed from wallet key following JavaScript pattern exactly
    auto seed_hex = knishio::KnishIOClient::generateSecret(key, 128);  // 128 hex chars = 64 bytes

    // Convert hex to bytes — full 64-byte seed, matching JS/Python
    std::vector<uint8_t> seed_bytes(64);
    for (size_t i = 0; i < 64; i++) {
        if (i * 2 + 1 < seed_hex.length()) {
            std::string hex_pair = seed_hex.substr(i * 2, 2);
            seed_bytes[i] = static_cast<uint8_t>(std::stoul(hex_pair, nullptr, 16));
        }
    }

    int result = 0;
    if (parameterSet == 1024) {
        identity.publicKey.resize(1568);
        identity.privateKey.resize(3168);
        result = mlkem1024_keypair_derand(
            identity.publicKey.data(),
            identity.privateKey.data(),
            seed_bytes.data()
        );
    } else {
        identity.publicKey.resize(1184);
        identity.privateKey.resize(2400);
        result = mlkem768_keypair_derand(
            identity.publicKey.data(),
            identity.privateKey.data(),
            seed_bytes.data()
        );
    }

    // Securely clear seed
    sodium_memzero(seed_bytes.data(), seed_bytes.size());

    if (result != 0) {
        throw std::runtime_error("Failed to generate ML-KEM keys");
    }

    return identity;
#else
    (void) parameterSet;
    throw std::runtime_error("ML-KEM not available");
#endif
}

void Wallet::initializeMLKEM(int parameterSet) {
#ifdef HAVE_MLKEM_NATIVE
    if (key.empty()) {
        return;
    }
    if (parameterSet == 768 || parameterSet == 1024) {
        mlkem_parameter_set = parameterSet;
    }

    MlKemIdentity identity = deriveMlKemKeypair(mlkem_parameter_set);
    mlkem_public_key = identity.publicKey;
    mlkem_private_key = identity.privateKey;

    // Update pubkey to ML-KEM public key (raw bytes)
    pubkey = mlkem_public_key;
#else
    (void) parameterSet;
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

std::map<std::string, std::string> Wallet::encryptMessageML(const std::string& message, const std::string& recipient_pubkey) {
#ifdef HAVE_MLKEM_NATIVE
    // Decode recipient public key from Base64
    auto recipient_key_bytes = fromBase64(recipient_pubkey);
    size_t expected_pk_bytes = (mlkem_parameter_set == 1024) ? 1568 : 1184;
    if (recipient_key_bytes.size() != expected_pk_bytes) {
        throw std::invalid_argument(
            "KnishIO: cannot ML-KEM-encrypt — recipient public key is " +
            std::to_string(recipient_key_bytes.size()) +
            " bytes, expected " + std::to_string(expected_pk_bytes) +
            " (ML-KEM-" + std::to_string(mlkem_parameter_set) + "). The peer is not running ML-KEM-" +
            std::to_string(mlkem_parameter_set) + "; upgrade the peer, or step this client back to the other parameter set.");
    }
    
    size_t ct_bytes = (mlkem_parameter_set == 1024) ? 1568 : 1088;
    std::vector<uint8_t> ciphertext(ct_bytes);
    std::vector<uint8_t> shared_secret(32);
    std::vector<uint8_t> coins(32);

    if (RAND_bytes(coins.data(), static_cast<int>(coins.size())) != 1) {
        sodium_memzero(coins.data(), coins.size());
        throw std::runtime_error("ML-KEM encapsulation RNG failed");
    }

    int result = 0;
    if (mlkem_parameter_set == 1024) {
        result = mlkem1024_enc_derand(
            ciphertext.data(),
            shared_secret.data(),
            recipient_key_bytes.data(),
            coins.data()
        );
    } else {
        result = mlkem768_enc_derand(
            ciphertext.data(),
            shared_secret.data(),
            recipient_key_bytes.data(),
            coins.data()
        );
    }
    sodium_memzero(coins.data(), coins.size());

    if (result != 0) {
        throw std::runtime_error("ML-KEM encapsulation failed");
    }

    // JSON-encode message (cross-SDK compatibility requirement)
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
    throw std::runtime_error("ML-KEM not available");
#endif
}

// ML-KEM decapsulate + AES-256-GCM decrypt → the RAW decrypted UTF-8 string (no JSON-decode).
// Shared by decryptMessageML (which JSON-decodes the result — the c136 vector + the PQ-transport
// REQUEST direction encrypt a JSON string value) and decryptMyMessageML (the PQ-transport
// RESPONSE direction, where the validator encrypts the response OBJECT → the raw plaintext is the
// inner GraphQL response JSON directly). PQ-transport Phase E.
//
// Inbound is PERMISSIVE: a ciphertext at EITHER parameter set decrypts, provided it is addressed
// to one of THIS wallet's own ML-KEM identities. The other identity is derived on demand and its
// private key is released with the scope of this call — never cached on the wallet. Outbound
// encapsulation stays STRICT (see encryptMessageML): reading a 768 record we own downgrades
// nothing, because that message's confidentiality was fixed at 768 by its sender, but
// encapsulating at 768 to a stale or hostile peer would be a real downgrade.
std::string Wallet::mlkemDecryptToString(const std::map<std::string, std::string>& encrypted_data) {
#ifdef HAVE_MLKEM_NATIVE
    auto ciphertext = fromBase64(encrypted_data.at("cipherText"));
    auto encrypted_message = fromBase64(encrypted_data.at("encryptedMessage"));

    const size_t configured_ct_bytes = (mlkem_parameter_set == 1024) ? 1568 : 1088;
    const int other_set = (mlkem_parameter_set == 1024) ? 768 : 1024;
    const size_t other_ct_bytes = (other_set == 1024) ? 1568 : 1088;

    // Decapsulate to recover shared secret
    std::vector<uint8_t> shared_secret(32);

    auto decapsulate = [](int parameterSet, uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
        return (parameterSet == 1024) ? mlkem1024_dec(ss, ct, sk) : mlkem768_dec(ss, ct, sk);
    };

    // ML-KEM secret keys are 2400 bytes (768) and 3168 bytes (1024), and mlkem*_dec reads that
    // many bytes from the pointer it is given. A secret-less wallet has an EMPTY key vector —
    // deriveMlKemKeypair() early-returns a default-constructed identity when `key` is empty — so
    // passing .data() unchecked would read out of bounds off a zero-length buffer. Both branches
    // therefore verify the key material's length before decapsulating.
    auto expected_sk_bytes = [](int parameterSet) -> size_t {
        return (parameterSet == 1024) ? 3168 : 2400;
    };

    int result = 0;
    if (ciphertext.size() == configured_ct_bytes) {
        if (mlkem_private_key.size() != expected_sk_bytes(mlkem_parameter_set)) {
            throw std::invalid_argument("ML-KEM private key unavailable for this wallet");
        }
        result = decapsulate(mlkem_parameter_set, shared_secret.data(), ciphertext.data(),
                             mlkem_private_key.data());
    } else if (ciphertext.size() == other_ct_bytes) {
        // Addressed to this wallet's OTHER identity: derive it, decapsulate, and let the derived
        // private key be zeroized as this block ends.
        MlKemIdentity derived = deriveMlKemKeypair(other_set);
        if (derived.privateKey.size() != expected_sk_bytes(other_set)) {
            throw std::invalid_argument("ML-KEM private key unavailable for this wallet");
        }
        result = decapsulate(other_set, shared_secret.data(), ciphertext.data(),
                             derived.privateKey.data());
    } else {
        throw std::invalid_argument("Invalid ML-KEM ciphertext size");
    }

    if (result != 0) {
        sodium_memzero(shared_secret.data(), shared_secret.size());
        throw std::runtime_error("ML-KEM decapsulation failed");
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
    throw std::runtime_error("ML-KEM not available");
#endif
}

std::string Wallet::decryptMessageML(const std::map<std::string, std::string>& encrypted_data) {
    std::string plaintext_json = mlkemDecryptToString(encrypted_data);
    try {
        json parsed = json::parse(plaintext_json);
        return parsed.get<std::string>();
    } catch (const std::exception& e) {
        return plaintext_json;
    }
}

// Canonical cross-SDK hashShare for a public key: standard base64 of SHAKE256(pubkey_utf8, 8 bytes)
// — byte-matches the validator's hash_share and the JS/Kotlin/PHP/TS/Python hashShare. NOTE
// shake256() takes a BIT length, so 64 bits = 8 bytes. PQ-transport Phase E.
std::string Wallet::hashShare(const std::string& pubkeyStr) {
    return toBase64(shake256(pubkeyStr, 64));
}

// Post-quantum (ML-KEM) CipherHash request envelope: a stringified single-recipient map
// { "<hashShare(recipient_pubkey)>": {cipherText, encryptedMessage} }. Matches the Rust validator's
// CipherHash handler. PQ-transport Phase E.
std::string Wallet::encryptStringML(const std::string& message, const std::string& recipient_pubkey) {
    auto envelope = encryptMessageML(message, recipient_pubkey);
    json map;
    map[hashShare(recipient_pubkey)] = envelope;
    return map.dump();
}

// Decrypt a CipherHash response map addressed to THIS wallet's ML-KEM pubkey → the RAW decrypted
// GraphQL response JSON text. Both of this wallet's identities' hash shares are tried: a pre-bump
// sender addressed the envelope to hashShare(our_768_pubkey), so a wallet configured at 1024 would
// otherwise return before the permissive length dispatch in mlkemDecryptToString() is ever
// reached. Returns an empty string when no entry matches.
std::string Wallet::decryptMyMessageML(const std::string& mapJson) {
    json map = json::parse(mapJson);
    std::string shareKey = hashShare(toBase64(mlkem_public_key));
    if (!map.contains(shareKey) && !mlkem_public_key.empty()) {
        const int other_set = (mlkem_parameter_set == 1024) ? 768 : 1024;
        shareKey = hashShare(toBase64(deriveMlKemKeypair(other_set).publicKey));
    }
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
