#include "Wallet.h"

#include "utility.h"
#include "crypto.h"
#include "third_party/BigInt/bigInt.h"

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
}

Wallet::~Wallet()
{
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
	return decryptMessage(encryptedMessage, this->pubkey, this->privkey);
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
	// Converting secret to bigInt
	auto bigIntSecret = BigInt::Rossi(secret, BigInt::HEX_DIGIT);
	// Adding new position to the user secret to produce the indexed key
	auto indexedKey = bigIntSecret + BigInt::Rossi(position, BigInt::HEX_DIGIT);
	// Hashing the indexed key to produce the intermediate key
	std::string intermediateKeySponge;

	intermediateKeySponge.append(indexedKey.toStrHex());

	if (!token.empty())
	{
		intermediateKeySponge.append(token);
	}

	// Hashing the intermediate key to produce the private key
	return shake256Hex(shake256Hex(intermediateKeySponge, 8192), 8192);
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
