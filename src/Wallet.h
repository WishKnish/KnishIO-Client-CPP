#pragma once

#include <string>

class Wallet
{
public:
	Wallet(const std::string &secret, const std::string &token = "USER", const std::string &position = {}, size_t saltLength = 64);
	~Wallet();

	static std::string generateBundleHash(const std::string &secret);
	static std::string generateWalletKey(const std::string &secret, const std::string &token, const std::string &position);
	static std::string generateWalletAddress(const std::string &key);

public:
	std::string position;
	std::string token;
	std::string key;
	std::string address;
	std::string balance;
	std::string molecules;
	std::string bundle;
};
