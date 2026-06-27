#pragma once

#include <string>
#include <vector>

// Classical NaCl (libsodium crypto_box_seal) public-key crypto — NON-post-quantum.
// The canonical post-quantum ML-KEM768 message envelope ({cipherText, encryptedMessage})
// is Wallet::encryptMessageML768 / decryptMessageML768 (see Wallet.h).
std::string encryptMessage(const std::string &messageUtf8, const std::vector<unsigned char> &recipientPublicKey);
std::string decryptMessage(const std::string &encryptedMessage, const std::vector<unsigned char> &recipientPublicKey, const std::vector<unsigned char> &recipientPrivateKey);

bool generatePublicAndPrivateKeys(std::vector<unsigned char> &publicKey, std::vector<unsigned char> &privateKey);
