#pragma once

#include "Atom.h"

class Wallet;

/**
 * class Molecule
 */
class Molecule
{
public:
	Molecule(const std::string &cellSlug = {});
	~Molecule();

	std::vector<Atom> initValue(const Wallet &sourceWallet, const Wallet &recipientWallet, const Wallet &remainderWallet, const std::string &value);
	std::vector<Atom> initTokenCreation(const Wallet &sourceWallet, const Wallet &recipientWallet, const std::string &amount
		, const std::map<std::string, std::string> &tokenMeta);
	std::vector<Atom> initMeta(const Wallet &wallet, const std::map<std::string, std::string> &meta, const std::string &metaType, const std::string &metaId);

	std::string sign(const std::string &secret, bool anonymous = false);

	std::string toJson() const;

	static Molecule jsonToObject(const std::string &json);
	static std::vector<char> enumerate(const std::string &hash);
	static std::vector<char> normalize(const std::vector<char> &mappedHashArray);
	static bool verify(const Molecule &molecule);
	static bool verifyMolecularHash(const Molecule &molecule);
	static bool verifyOts(const Molecule &molecule);
	static bool verifyTokenIsotopeV(const Molecule &molecule);

public:
	std::string					molecularHash;
	std::string					cellSlug;
	std::string					bundle;
	std::string					status;
	std::vector<Atom>			atoms;
	std::chrono::milliseconds	createdAt;
};

