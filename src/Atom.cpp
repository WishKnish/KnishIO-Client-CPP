#include "Atom.h"

#include "third_party/nlohmann/json.hpp"
#include "third_party/Keccak/Keccak.h"
#include "utility.h"
#include <algorithm>
#include <array>
#include <numeric>

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
		"index",
		"version",
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
					atom.parsedEmpty.set(EmptyValue, atom.value.empty());
				}
				break;

			case 5:
				if (!value->is_null()) {
					atom.batchId = value->get<std::string>();
					atom.parsedEmpty.set(EmptyBatchId, atom.batchId.empty());
				}
				break;

			case 6:
				if (!value->is_null()) {
					atom.metaType = value->get<std::string>();
					atom.parsedEmpty.set(EmptyMetaType, atom.metaType.empty());
				}
				break;

			case 7:
				if (!value->is_null()) {
					atom.metaId = value->get<std::string>();
					atom.parsedEmpty.set(EmptyMetaId, atom.metaId.empty());
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
							atom.nullMeta.push_back({metaValues.size() + atom.nullMeta.size(), key});
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
				auto createdAt = value->is_number_integer()
					? value->get<long long>()
					: std::strtoll(value->get<std::string>().c_str(), NULL, 10);

				atom.createdAt = std::chrono::milliseconds(createdAt);
				break;
			}

			case 11:
				if (value->is_number_integer()) {
					atom.index = value->get<int>();
				}
				break;

			case 12:
				if (value->is_string()) {
					atom.version = value->get<std::string>();
				} else if (value->is_number()) {
					atom.version = value->dump();
				}
				break;

			default:
				break;
			}
		}
	}

	return atom;
}

std::string Atom::version4ViewJson(const std::vector<Atom> &atoms)
{
	std::vector<size_t> order(atoms.size());
	std::iota(order.begin(), order.end(), size_t{0});
	std::stable_sort(order.begin(), order.end(), [&atoms](size_t a, size_t b) { return atoms[a].index < atoms[b].index; });

	const auto field = [](const std::string &s) { return s.empty() ? nlohmann::json(nullptr) : nlohmann::json(s); };
	const auto entry = [](const char *key, nlohmann::json value) {
		nlohmann::json object = nlohmann::json::object();
		object[key] = std::move(value);
		return object;
	};
	const auto metaItem = [&entry](const std::string &key, nlohmann::json value) {
		return nlohmann::json::array({entry("key", key), entry("value", std::move(value))});
	};

	nlohmann::json views = nlohmann::json::array();
	for (const size_t i : order)
	{
		const Atom &atom = atoms[i];
		const auto optional = [&atom, &field](const std::string &s, ParsedEmptyField f) {
			return atom.parsedEmpty.test(f) ? nlohmann::json(s) : field(s);
		};

		// Null meta items go back to their parsed positions.
		nlohmann::json meta = nlohmann::json::array();
		auto nullIt = atom.nullMeta.begin();
		for (const auto &pair : atom.meta)
		{
			for (; nullIt != atom.nullMeta.end() && nullIt->first <= meta.size(); ++nullIt) {
				meta.push_back(metaItem(nullIt->second, nullptr));
			}
			meta.push_back(metaItem(pair.first, pair.second));
		}
		for (; nullIt != atom.nullMeta.end(); ++nullIt) {
			meta.push_back(metaItem(nullIt->second, nullptr));
		}

		views.push_back(nlohmann::json::array({
			entry("batchId", optional(atom.batchId, EmptyBatchId)),
			entry("createdAt", std::to_string(atom.createdAt.count())),
			entry("index", atom.index),
			entry("isotope", field(atom.isotope)),
			entry("meta", std::move(meta)),
			entry("metaId", optional(atom.metaId, EmptyMetaId)),
			entry("metaType", optional(atom.metaType, EmptyMetaType)),
			entry("position", field(atom.position)),
			entry("token", field(atom.token)),
			entry("value", optional(atom.value, EmptyValue)),
			entry("version", atom.version ? nlohmann::json(*atom.version) : nlohmann::json(nullptr)),
			entry("walletAddress", field(atom.walletAddress)),
		}));
	}

	return views.dump();
}

std::vector<unsigned char> Atom::hashAtoms(const std::vector<Atom> &atoms)
{
	// Every atom carries a version (any value): hash the Version4 structured view.
	if (!atoms.empty() && std::all_of(atoms.begin(), atoms.end(), [](const Atom &a) { return a.version.has_value(); })) {
		return shake256(version4ViewJson(atoms), 256);
	}

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
