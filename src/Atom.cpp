#include "Atom.h"

#include "third_party/nlohmann/json.hpp"
#include "third_party/Keccak/Keccak.h"
#include "utility.h"
#include <array>

using namespace std::chrono;

namespace KnishIO {

/**
 * class Atom
 *
 */
Atom::Atom(const std::string &position, const std::string &walletAddress, const std::string &isotope, const std::string &token, const std::string &value
	, const std::string &batchId, const std::string &metaType, const std::string &metaId, const std::vector<std::pair<std::string, std::string>> &meta, const std::string &otsFragment, int index)
	: position(position)
	, walletAddress(walletAddress)
	, isotope(isotope)
	, token(token)
	, value(value)
	, batchId(batchId)
	, metaType(metaType)
	, metaId(metaId)
	, meta(meta)
	, otsFragment(otsFragment)
	, createdAt(duration_cast<milliseconds>(system_clock::now().time_since_epoch()))
	, index(index)
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
		"batchId",
		"metaType",
		"metaId",
		"meta",
		"otsFragment",
		"createdAt",
	};

	nlohmann::json json = nlohmann::json::parse(jsonStr);

	Atom atom("", "", "");

	for (size_t i = 0; i < std::size(c_values); i++)
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
				if (!value->is_null()) {
					atom.value = value->get<std::string>();
				}
				break;

			case 5:
				if (!value->is_null()) {
					atom.batchId = value->get<std::string>();
				}
				break;

			case 6:
				if (!value->is_null()) {
					atom.metaType = value->get<std::string>();
				}
				break;

			case 7:
				if (!value->is_null()) {
					atom.metaId = value->get<std::string>();
				}
				break;

			case 8:
			{
				std::vector<std::pair<std::string, std::string>> metaValues;

				for (auto &key_value : *value)
				{
					if (key_value.find("key") != key_value.end() && key_value.find("value") != key_value.end())
					{
						auto key = key_value["key"].get<std::string>();
						const auto &metaVal = key_value["value"];

						// Cross-SDK meta values are not always strings: an absent optional key (e.g.
						// walletBatchId) may be serialized as null — every SDK SKIPS null meta in the
						// molecular hash, so skip it here too (else the re-hash diverges); a flag like
						// shadowWalletClaim may be serialized as the number 1 — stringify scalars to
						// their canonical text ("1") so the re-hash matches the producer.
						if (metaVal.is_null()) {
							continue;
						}
						auto value = metaVal.is_string() ? metaVal.get<std::string>() : metaVal.dump();

						metaValues.push_back({key, value});
					}
				}

				atom.meta = metaValues;
				break;
			}

			case 9:
				if (!value->is_null()) {
					atom.otsFragment = value->get<std::string>();
				}
				break;

			case 10:
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
		// Number of atoms (appended per atom — matches JavaScript/C logic)
		molecularSponge.append(std::to_string(atoms.size()));

		// Required fields
		molecularSponge.append(atom.position);
		molecularSponge.append(atom.walletAddress);
		molecularSponge.append(atom.isotope);

		// Optional fields — appended only when non-empty (matches JavaScript/C logic)
		if (!atom.token.empty()) {
			molecularSponge.append(atom.token);
		}
		if (!atom.value.empty()) {
			molecularSponge.append(atom.value);
		}
		if (!atom.batchId.empty()) {
			molecularSponge.append(atom.batchId);
		}
		if (!atom.metaType.empty()) {
			molecularSponge.append(atom.metaType);
		}
		if (!atom.metaId.empty()) {
			molecularSponge.append(atom.metaId);
		}

		// Meta key/value pairs (every pair, even empty values — matches JavaScript/C logic)
		for (const auto &meta : atom.meta)
		{
			molecularSponge.append(meta.first);   // key
			molecularSponge.append(meta.second);  // value (even if empty string)
		}

		// createdAt (required field)
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

} // namespace KnishIO
