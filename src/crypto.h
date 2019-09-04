#pragma once

#include <string>
#include <vector>

std::string encryptMessage(const std::string &messageUtf8, const std::vector<unsigned char> &recipientPublicKey);
std::string decryptMessage(const std::string &encryptedMessage, const std::vector<unsigned char> &recipientPublicKey, const std::vector<unsigned char> &recipientPrivateKey);

bool generatePublicAndPrivateKeys(std::vector<unsigned char> &publicKey, std::vector<unsigned char> &privateKey);
