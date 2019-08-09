#include "Molecule.h"

#include <chrono>

#include "third_party/BigInt/bigInt.h"
#include "Wallet.h"
#include "utility.h"
#include "AtomsNotFoundException.h"
#include "third_party/nlohmann/json.hpp"

using namespace std::chrono;

Molecule::Molecule(const std::string &cellSlug)
	: cellSlug(cellSlug)
	, createdAt(duration_cast<milliseconds>(system_clock::now().time_since_epoch()))
{
}

Molecule::~Molecule()
{
}

/**
  * Initialize a V-type molecule to transfer value from one wallet to another, with a third,
  * regenerated wallet receiving the remainder
  *
  * @param {Wallet} sourceWallet
  * @param {Wallet} recipientWallet
  * @param {Wallet} remainderWallet
  * @param {*} value
  * @returns {Array}
  */
std::vector<Atom> Molecule::initValue(const Wallet &sourceWallet, const Wallet &recipientWallet, const Wallet &remainderWallet, const std::string &value)
{
	this->molecularHash.clear();

	auto position = BigInt::Rossi(sourceWallet.position, BigInt::HEX_DIGIT);

	using namespace std;

	// Initializing a new Atom to remove tokens from source
	this->atoms.push_back
	(
		Atom(position.toStrHex(),
			sourceWallet.address,
			"V",
			sourceWallet.token,
			"-" + value,
			"remainderWallet",
			remainderWallet.address,
			map<string, string> { make_pair("remainderPosition", remainderWallet.position) })
	);

	// Initializing a new Atom to add tokens to recipient
	this->atoms.push_back
	(
		Atom((position + 1).toStrHex(),
			recipientWallet.address,
			"V",
			sourceWallet.token,
			value,
			"walletBundle",
			recipientWallet.bundle)
	);

	return this->atoms;
}

/**
 * Initialize a C-type molecule to issue a new type of token
 *
 * @param {Wallet} sourceWallet - wallet signing the transaction. This should ideally be the USER wallet.
 * @param {Wallet} recipientWallet - wallet receiving the tokens. Needs to be initialized for the new token beforehand.
 * @param {number} amount - how many of the token we are initially issuing (for fungible tokens only)
 * @param {Array | Object} tokenMeta - additional fields to configure the token
 * @returns {Array}
 */
std::vector<Atom> Molecule::initTokenCreation(const Wallet &sourceWallet, const Wallet &recipientWallet, const std::string &amount
	, const std::map<std::string, std::string> &tokenMeta)
{
	this->molecularHash.clear();

	auto tokenMetaNew = tokenMeta;

	// tokenMeta: add fields address and position if not presented
	auto itToken = tokenMetaNew.find("walletAddress");

	if (itToken == tokenMetaNew.end())
	{
		tokenMetaNew["address"] = recipientWallet.address;
	}

	itToken = tokenMetaNew.find("walletPosition");

	if (itToken == tokenMetaNew.end())
	{
		tokenMetaNew["position"] = recipientWallet.position;
	}

	// The primary atom tells the ledger that a certain amount of the new token is being issued.
	this->atoms.push_back
	(
		Atom(sourceWallet.position,
			sourceWallet.address,
			"C",
			sourceWallet.token,
			amount,
			"token",
			recipientWallet.token,
			tokenMetaNew)
	);

	return this->atoms;
}

/**
   * Initialize an M-type molecule with the given data
   *
   * @param {Wallet} wallet
   * @param {Array | Object} meta
   * @param {string} metaType
   * @param {string} metaId
   * @returns {Array}
   */
std::vector<Atom> Molecule::initMeta(const Wallet &wallet, const std::map<std::string, std::string> &meta, const std::string &metaType, const std::string &metaId)
{
	this->molecularHash.clear();

	// Initializing a new Atom to hold our metadata
	this->atoms.push_back
	(
		Atom(wallet.position,
			wallet.address,
			"M",
			wallet.token,
			{},
			metaType,
			metaId,
			meta)
	);

	return this->atoms;
}

/**
   * Creates a one-time signature for a molecule and breaks it up across multiple atoms within that
   * molecule. Resulting 4096 byte (2048 character) string is the one-time signature.
   *
   * @param {string} secret
   * @param {boolean} anonymous
   * @returns {*}
   * @throws {AtomsNotFoundException}
   */
std::string Molecule::sign(const std::string &secret, bool anonymous)
{
	if (this->atoms.empty())
	{
		throw AtomsNotFoundException();
	}

	if (!anonymous)
	{
		this->bundle = Wallet::generateBundleHash(secret);
	}

	this->molecularHash = Atom::hashAtomsBase17(this->atoms);

	// Generate the private signing key for this molecule
	auto key = Wallet::generateWalletKey(secret, this->atoms.front().token, this->atoms.front().position);

	// Subdivide Kk into 16 segments of 256 bytes (128 characters) each
	auto keyChunks = chunkSubstr(key, 128);

	// Convert Hm to numeric notation, and then normalize
	auto normalizedHash = Molecule::normalize(Molecule::enumerate(this->molecularHash));

	// Building a one-time-signature
	std::string signatureFragments;

	for (size_t index = 0; index < keyChunks.size(); index++)
	{
		auto workingChunk = keyChunks[index];

		for (int iterationCount = 0, condition = 8 - normalizedHash[index]; iterationCount < condition; iterationCount++)
		{
			workingChunk = shake256Hex(workingChunk, 512);
		}

		signatureFragments += workingChunk;
	}

	// Chunking the signature across multiple atoms
	auto chunkedSignature = chunkSubstr(signatureFragments, (size_t)std::round((double)signatureFragments.size() / this->atoms.size()));

	std::string lastPosition;

	for (size_t chunkCount = 0, condition = chunkedSignature.size(); chunkCount < condition; chunkCount++)
	{
		this->atoms[chunkCount].otsFragment = chunkedSignature[chunkCount];
		lastPosition = this->atoms[chunkCount].position;
	}

	return lastPosition;
}

std::string Molecule::toJson() const
{
	nlohmann::json jsonMolecule;

	jsonMolecule["molecularHash"] = this->molecularHash;
	jsonMolecule["cellSlug"] = this->cellSlug;
	jsonMolecule["bundle"] = this->bundle;
	jsonMolecule["status"] = this->status;
	jsonMolecule["createdAt"] = std::to_string(this->createdAt.count());

	jsonMolecule["atoms"] = nlohmann::json::array();

	for (const auto &atom : this->atoms)
	{
		nlohmann::json jsonAtom;

		jsonAtom["position"] = atom.position;
		jsonAtom["walletAddress"] = atom.walletAddress;
		jsonAtom["isotope"] = atom.isotope;
		jsonAtom["token"] = atom.token;
		jsonAtom["value"] = atom.value;
		jsonAtom["metaType"] = atom.metaType;
		jsonAtom["metaId"] = atom.metaId;

		// write meta
		jsonAtom["meta"] = nlohmann::json::array();

		for (auto &meta : atom.meta)
		{
			nlohmann::json jsonMeta;
			jsonMeta["key"] = meta.first;
			jsonMeta["value"] = meta.second;

			jsonAtom["meta"].push_back(jsonMeta);
		}

		jsonAtom["otsFragment"] = atom.otsFragment;
		jsonAtom["createdAt"] = std::to_string(atom.createdAt.count());

		jsonMolecule["atoms"].push_back(jsonAtom);
	}

	return jsonMolecule.dump();
}

/**
  * @param {string} json
  * @return {Object}
  * @throws {AtomsNotFoundException}
  */
Molecule Molecule::jsonToObject(const std::string &jsonStr)
{
	nlohmann::json json = nlohmann::json::parse(jsonStr);

	Molecule molecule;

	auto value = json.find("molecularHash");

	if (value != json.end())
	{
		molecule.molecularHash = value->get<std::string>();
	}

	value = json.find("cellSlug");

	if (value != json.end())
	{
		molecule.cellSlug = value->get<std::string>();
	}

	value = json.find("bundle");

	if (value != json.end())
	{
		molecule.bundle = value->get<std::string>();
	}

	value = json.find("status");

	if (value != json.end())
	{
		molecule.status = value->get<std::string>();
	}

	value = json.find("atoms");

	if (value != json.end())
	{
		for (auto &jsonAtom : *value)
		{
			auto atom = Atom::jsonToObject(jsonAtom.dump());

			if (atom.position.empty()
				|| atom.walletAddress.empty()
				|| atom.isotope.empty())
			{
				throw AtomsNotFoundException("The required properties of the atom are not filled.");
			}

			molecule.atoms.push_back(atom);
		}
	}

	value = json.find("createdAt");

	if (value != json.end())
	{
		auto createdAtStr = value->get<std::string>();
		auto createdAt = std::strtoll(createdAtStr.c_str(), NULL, 10);

		molecule.createdAt = std::chrono::milliseconds(createdAt);
	}

	return molecule;
}

bool Molecule::verify(const Molecule &molecule)
{
	return verifyMolecularHash(molecule)
		&& verifyOts(molecule)
		&& verifyTokenIsotopeV(molecule);
}

/**
   * Verifies if the hash of all the atoms matches the molecular hash to ensure content has not been messed with
   *
   * @param {Molecule} molecule
   * @return {boolean}
   */
bool Molecule::verifyMolecularHash(const Molecule &molecule)
{
	if (!molecule.atoms.empty() && !molecule.molecularHash.empty())
	{
		auto atomicHash = Atom::hashAtomsBase17(molecule.atoms);

		return (atomicHash == molecule.molecularHash);
	}

	return false;
}

/**
   * Checks if the provided molecule was signed properly by transforming a collection of signature
   * fragments from its atoms and its molecular hash into a single-use wallet address to be matched
   * against the sender’s address. If it matches, the molecule was correctly signed.
   *
   * @param {Molecule} molecule
   * @returns {boolean}
   */
bool Molecule::verifyOts(const Molecule &molecule)
{
	if (molecule.atoms.empty() || molecule.molecularHash.empty())
	{
		return false;
	}

	auto atoms = molecule.atoms;

	std::sort(atoms.begin(), atoms.end());

	// Convert Hm to numeric notation via EnumerateMolecule(Hm)
	auto enumeratedHash = Molecule::enumerate(molecule.molecularHash);
	auto normalizedHash = Molecule::normalize(enumeratedHash);

	std::string ots;

	for (auto &atom : atoms)
	{
		ots += atom.otsFragment;
	}

	// Subdivide Kk into 16 segments of 256 bytes (128 characters) each
	auto otsChunks = chunkSubstr(ots, 128);

	std::string keyFragments;

	for (size_t index = 0; index < otsChunks.size(); index++)
	{
		auto workingChunk = otsChunks[index];

		for (int iterationCount = 0, condition = 8 + normalizedHash[index]; iterationCount < condition; iterationCount++)
		{
			workingChunk = shake256Hex(workingChunk, 512);
		}

		keyFragments += workingChunk;
	}

	// Absorb the hashed Kk into the sponge to receive the digest Dk
	auto digest = shake256Hex(keyFragments, 8192);
	// Squeeze the sponge to retrieve a 128 byte (64 character) string that should match the sender’s wallet address
	auto address = shake256Hex(digest, 256);

	return (address == atoms.front().walletAddress);
}

/**
   * @param {Molecule} molecule
   * @return {boolean}
   * @throws {TypeError}
   */
bool Molecule::verifyTokenIsotopeV(const Molecule &molecule)
{
	if (molecule.atoms.empty() || molecule.molecularHash.empty())
	{
		return false;
	}
	
	// summ of V-isotope values for each token should be 0
	for (auto itAtom = molecule.atoms.begin(); itAtom != molecule.atoms.end(); ++itAtom)
	{
		if (itAtom->isotope != "V")
		{
			continue;
		}

		// check token was processed already
		auto token = itAtom->token;

		auto itAtomPrev = std::find_if(molecule.atoms.begin(), itAtom, [&token](const Atom &atom)
		{
			return (atom.token == token);
		});

		if (itAtomPrev != itAtom)
		{
			continue;
		}

		// get summ of V-isotope values for token
		double result = 0;

		for (auto itAtomToken = itAtom; itAtomToken != molecule.atoms.end(); ++itAtomToken)
		{
			if (itAtomToken->isotope != "V" || itAtomToken->token != itAtom->token)
			{
				continue;
			}

			char *end = nullptr;
			double value = strtod(itAtomToken->value.c_str(), &end);

			// verify value
			if (end == nullptr || end != itAtomToken->value.data() + itAtomToken->value.size())
			{
				throw std::exception("Invalid isotope \"V\" values");
			}

			result += value;
		}

		if (result != 0)
		{
			return false;
		}
	}

	return true;
}

/**
  * Accept a string of letters and numbers, and outputs a collection of decimals representing each
  * character according to a pre-defined dictionary. Input string would typically be 64-character
  * hexadecimal string featuring numbers from 0 to 9 and characters from a to f - a total of 15
  * unique symbols. To ensure that string has an even number of symbols, convert it to Base 17
  * (adding G as a possible symbol). Map each symbol to integer values as follows:
  *  0   1   2   3   4   5   6   7  8  9  a   b   c   d   e   f   g
  * -8  -7  -6  -5  -4  -3  -2  -1  0  1  2   3   4   5   6   7   8
  *
  * @param {string} hash
  * @returns {Array}
  */
std::vector<char> Molecule::enumerate(const std::string &hash)
{
	std::vector<char> target;
	target.reserve(hash.size());

	for (auto &c : hash)
	{
		char val;

		switch (c)
		{
			case '0': val = -8; break;
			case '1': val = -7; break;
			case '2': val = -6; break;
			case '3': val = -5; break;
			case '4': val = -4; break;
			case '5': val = -3; break;
			case '6': val = -2; break;
			case '7': val = -1; break;
			case '8': val = 0; break;
			case '9': val = 1; break;
			case 'a': val = 2; break;
			case 'b': val = 3; break;
			case 'c': val = 4; break;
			case 'd': val = 5; break;
			case 'e': val = 6; break;
			case 'f': val = 7; break;
			case 'g': val = 8; break;
			default: continue;
		}

		target.push_back(val);
	}

	return target;
}

/**
  * Normalize enumerated string to ensure that the total sum of all symbols is exactly zero. This
  * ensures that exactly 50% of the WOTS+ key is leaked with each usage, ensuring predictable key
  * safety:
  * The sum of each symbol within Hm shall be presented by m
  *  While m0 iterate across that set’s integers as Im:
  *    If m0 and Im>-8 , let Im=Im-1
  *    If m<0 and Im<8 , let Im=Im+1
  *    If m=0, stop the iteration
  *
  * @param {Array} mappedHashArray
  * @returns {*}
  */
std::vector<char> Molecule::normalize(const std::vector<char> &mappedHashArray)
{
	int total = 0;

	for (auto &c : mappedHashArray)
	{
		total += c;
	}

	bool total_condition = (total < 0);

	std::vector<char> mappedHashArrayOut = mappedHashArray;

	while (total != 0)
	{
		for (auto &c : mappedHashArrayOut)
		{
			bool condition = (total_condition ? c < 8 : c > -8);

			if (condition)
			{
				if (total_condition)
				{
					c++;
					total++;
				}
				else
				{
					c--;
					total--;
				}

				if (total == 0) break;
			}
		}
	}

	return mappedHashArrayOut;
}
