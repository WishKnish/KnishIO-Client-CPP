#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include "TokenUnit.h"

namespace KnishIO {

class Wallet
{
public:
	Wallet(const std::string &secret, const std::string &token = "USER", const std::string &position = {}, size_t saltLength = 64);
	~Wallet();

	bool generateMyPublicAndPrivateKeys();
	std::string decryptMyMessage(const std::string &message);

	// ML-KEM768 post-quantum cryptography methods (JavaScript SDK compatibility)
	void initializeMLKEM();
	std::map<std::string, std::string> encryptMessageML768(const std::string& message, const std::string& recipient_pubkey);
	std::string decryptMessageML768(const std::map<std::string, std::string>& encrypted_data);

private:
	// AES-256-GCM helper methods for ML-KEM768 message encryption
	std::vector<uint8_t> encryptWithSharedSecret(const std::vector<uint8_t>& message, const std::vector<uint8_t>& shared_secret);
	std::vector<uint8_t> decryptWithSharedSecret(const std::vector<uint8_t>& encrypted_message, const std::vector<uint8_t>& shared_secret);

public:

	static std::string generateBundleHash(const std::string &secret);
	static std::string generateWalletKey(const std::string &secret, const std::string &token, const std::string &position);
	static std::string generateWalletAddress(const std::string &key);

	// Stackable (NFT) token units. splitUnits partitions this wallet's units across the SENT set
	// (id ∈ units; kept on this wallet + copied to recipientWallet if non-null) and the KEPT set
	// (remainderWallet). getTokenUnitsJson() serializes them to the canonical [[id,name,metas],...]
	// JSON used as the `tokenUnits` V-atom meta. Mirrors JS/Rust/Python/C.
	void splitUnits(const std::vector<std::string> &units, Wallet &remainderWallet, Wallet *recipientWallet = nullptr);
	std::string getTokenUnitsJson() const;

public:
	std::string position;
	std::string token;
	std::string key;
	std::string address;
	std::string balance;
	std::string batchId;   // optional batch id (shadow-wallet claims / batched transfers)
	std::string molecules;
	std::string bundle;
	std::vector<TokenUnit> tokenUnits;   // stackable (NFT) token units carried by this wallet
	std::vector<unsigned char> privkey;
	std::vector<unsigned char> pubkey;

	// ML-KEM768 post-quantum cryptography keys (JavaScript SDK compatibility)
	std::vector<uint8_t> mlkem_public_key;
	std::vector<uint8_t> mlkem_private_key;
};

} // namespace KnishIO
