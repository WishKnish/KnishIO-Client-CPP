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
	Wallet(const std::string &secret, const std::string &token = "USER", const std::string &position = {}, size_t saltLength = 64, int mlkemParameterSet = 1024);
	~Wallet();

	bool generateMyPublicAndPrivateKeys();
	std::string decryptMyMessage(const std::string &message);

	// ML-KEM post-quantum cryptography methods (JavaScript SDK compatibility)
	void initializeMLKEM(int parameterSet = 1024);
	std::map<std::string, std::string> encryptMessageML(const std::string& message, const std::string& recipient_pubkey);
	std::string decryptMessageML(const std::map<std::string, std::string>& encrypted_data);

	// PQ-transport (Phase E): the canonical ML-KEM CipherHash transport helpers.
	std::string hashShare(const std::string& pubkey);
	std::string encryptStringML(const std::string& message, const std::string& recipient_pubkey);
	std::string decryptMyMessageML(const std::string& mapJson);
	std::string mlkemDecryptToString(const std::map<std::string, std::string>& encrypted_data);

private:
	// A derived ML-KEM identity. The 64-byte d‖z seed this wallet's key produces takes no
	// parameter-set input, so BOTH the ML-KEM-768 and the ML-KEM-1024 identity are derivable
	// from material the wallet already holds. The private key is zeroized when the value
	// leaves scope — a derived key is never cached on the wallet.
	struct MlKemIdentity
	{
		std::vector<uint8_t> publicKey;
		std::vector<uint8_t> privateKey;
		int parameterSet = 0;

		MlKemIdentity() = default;
		MlKemIdentity(const MlKemIdentity&) = delete;
		MlKemIdentity& operator=(const MlKemIdentity&) = delete;
		MlKemIdentity(MlKemIdentity&&) noexcept = default;
		~MlKemIdentity();
	};

	// Derives a keypair at an arbitrary parameter set (768 or 1024) WITHOUT mutating the wallet.
	// initializeMLKEM() calls it with the configured set; inbound decryption calls it with the
	// other set when a ciphertext or hash share belongs to this wallet's other identity.
	MlKemIdentity deriveMlKemKeypair(int parameterSet) const;

	// AES-256-GCM helper methods for ML-KEM message encryption
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
	// N-way sibling of splitUnits (multi-recipient stackable transfer): the source keeps the SENT
	// union, each recipientWallets[i] gets its own subset (recipientUnitLists[i]), and remainderWallet
	// keeps the KEPT units. recipientUnitLists is parallel to recipientWallets.
	void splitUnitsMulti(const std::vector<std::vector<std::string>> &recipientUnitLists, std::vector<Wallet> &recipientWallets, Wallet &remainderWallet);
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

	// ML-KEM post-quantum cryptography keys (JavaScript SDK compatibility)
	std::vector<uint8_t> mlkem_public_key;
	std::vector<uint8_t> mlkem_private_key;
	int mlkem_parameter_set = 1024;
};

} // namespace KnishIO
