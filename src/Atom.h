// Copyright 2019 WishKnish Corp. All rights reserved.
// You may use, distribute, and modify this code under the GPLV3 license, which is provided at:
// https://github.com/WishKnish/KnishIO-Client-JS/blob/master/LICENSE
// This experimental code is part of the Knish.IO API Client and is provided AS IS with no warranty whatsoever.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>
#include <utility>
#include <bitset>
#include <cstdint>

namespace KnishIO {

/**
 * class Atom
 *
 */
class Atom
{
public:
	Atom(const std::string &position, const std::string &walletAddress, const std::string &isotope
		, const std::string &token = {}, const std::string &value = {}, const std::string &batchId = {}, const std::string &metaType = {}
		, const std::string &metaId = {}, const std::vector<std::pair<std::string, std::string>> &meta = {}, const std::string &otsFragment = {}, int index = 0);

	static Atom jsonToObject(const std::string &json);

	static std::vector<unsigned char> hashAtoms(const std::vector<Atom> &atoms);
	// The Version4 structured view the molecular hash covers when every atom carries a version
	// (any value): the atoms sorted by index, each a JSON array of 12 single-key objects
	// (batchId, createdAt, index, isotope, meta, metaId, metaType, position, token, value,
	// version, walletAddress), serialized compactly. An empty string field is written as null,
	// except batchId, metaId, metaType and value parsed as "" (see parsedEmpty), which stay "".
	static std::string version4ViewJson(const std::vector<Atom> &atoms);
	static std::string hashAtomsHex(const std::vector<Atom> &atoms);
	static std::string hashAtomsBase17(const std::vector<Atom> &atoms);

public:
	std::string												position;
	std::string												walletAddress;
	std::string												isotope;
	std::string												token;
	std::string												value;
	std::string												batchId;
	std::string												metaType;
	std::string												metaId;
	std::vector<std::pair<std::string, std::string>>		meta;
	std::string												otsFragment;
	std::chrono::milliseconds								createdAt;
	int														index = 0;  // Atom index for JavaScript canonical compliance
	// Atom version as served or parsed ("version" in client-format JSON); absent when unset.
	// Never set when signing, and emitted by Molecule::toJson only when present.
	std::optional<std::string>								version;
	// Meta items parsed with a null value: (position in the parsed meta list, key). The legacy
	// hash skips them; the Version4 view keeps them in place with a null value.
	std::vector<std::pair<size_t, std::string>>			nullMeta;
	// Optional fields jsonToObject read as "" rather than null or absent. The legacy hash skips
	// every empty field; the Version4 view writes these as "" and other empty fields as null.
	enum ParsedEmptyField : std::uint8_t { EmptyValue, EmptyBatchId, EmptyMetaType, EmptyMetaId, ParsedEmptyFieldCount };
	std::bitset<ParsedEmptyFieldCount>						parsedEmpty;
};

} // namespace KnishIO
