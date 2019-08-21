#include "Atom.h"

#include "third_party/nlohmann/json.hpp"
#include "third_party/Keccak/Keccak.h"
#include "utility.h"

using namespace std::chrono;

/**
 * class Atom
 *
 */
Atom::Atom(const std::string &position, const std::string &walletAddress, const std::string &isotope, const std::string &token, const std::string &value
	, const std::string &metaType, const std::string &metaId, const std::map<std::string, std::string> &meta, const std::string &otsFragment)
	: position(position)
	, walletAddress(walletAddress)
	, isotope(isotope)
	, token(token)
	, value(value)
	, metaType(metaType)
	, metaId(metaId)
	, meta(meta)
	, otsFragment(otsFragment)
	, createdAt(duration_cast<milliseconds>(system_clock::now().time_since_epoch()))
{
}

Atom Atom::jsonToObject(const std::string &jsonStr)
{
	const char *c_values[] =
	{
		"position",
		"walletAddress",
		"isotope",
		"token",
		"value",
		"metaType",
		"metaId",
		"meta",
		"otsFragment",
		"createdAt",
	};

	nlohmann::json json = nlohmann::json::parse(jsonStr);

	Atom atom("", "", "");

	for (size_t i = 0; i < _countof(c_values); i++)
	{
		auto value = json.find(c_values[i]);

		if (value != json.end())
		{
			switch (i)
			{
			case 0:
				atom.position = value->get<std::string>();
				break;

			case 1:
				atom.walletAddress = value->get<std::string>();
				break;

			case 2:
				atom.isotope = value->get<std::string>();
				break;

			case 3:
				atom.token = value->get<std::string>();
				break;

			case 4:
				atom.value = value->get<std::string>();
				break;

			case 5:
				atom.metaType = value->get<std::string>();
				break;

			case 6:
				atom.metaId = value->get<std::string>();
				break;

			case 7:
			{
				std::map<std::string, std::string> metaValues;

				for (auto &key_value : *value)
				{
					if (key_value.find("key") != key_value.end() && key_value.find("value") != key_value.end())
					{
						auto key = key_value["key"].get<std::string>();
						auto value = key_value["value"].get<std::string>();

						metaValues[key] = value;
					}
				}

				atom.meta = metaValues;
				break;
			}

			case 8:
				atom.otsFragment = value->get<std::string>();
				break;

			case 9:
			{
				auto createdAtStr = value->get<std::string>();
				auto createdAt = std::strtoll(createdAtStr.c_str(), NULL, 10);

				atom.createdAt = std::chrono::milliseconds(createdAt);
				break;
			}

			}
		}
	}

	return atom;
}

std::vector<unsigned char> Atom::hashAtoms(const std::vector<Atom> &atoms)
{
	std::string molecularSponge;

	for (const auto &atom : atoms)
	{
		molecularSponge.append(std::to_string(atoms.size()));

		molecularSponge.append(atom.position);
		molecularSponge.append(atom.walletAddress);
		molecularSponge.append(atom.isotope);
		molecularSponge.append(atom.token);
		molecularSponge.append(atom.value);
		molecularSponge.append(atom.metaType);
		molecularSponge.append(atom.metaId);

		for (const auto &meta : atom.meta)
		{
			molecularSponge.append(meta.first); // key
			molecularSponge.append(meta.second.empty() ? "null" : meta.second); // value
		}

		molecularSponge.append(std::to_string(atom.createdAt.count()));
	}

	return shake256(molecularSponge, 256);
}

std::string Atom::hashAtomsHex(const std::vector<Atom> &atoms)
{
	auto hash = hashAtoms(atoms);

	return toHexString(hash);
}

std::string Atom::hashAtomsBase17(const std::vector<Atom> &atoms)
{
	auto hashHex = hashAtomsHex(atoms);

	auto hashConverted = charsetBaseConvert(hashHex, 16, 17, "0123456789abcdefg");

	// pad with zeroes in the beginning
	hashConverted.insert(hashConverted.begin(), hashConverted.size() < 64 ? 64 - hashConverted.size() : 0, '0');

	return hashConverted;
}
