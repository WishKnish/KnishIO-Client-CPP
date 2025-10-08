// Copyright 2019 WishKnish Corp. All rights reserved.
// You may use, distribute, and modify this code under the GPLV3 license, which is provided at:
// https://github.com/WishKnish/KnishIO-Client-JS/blob/master/LICENSE
// This experimental code is part of the Knish.IO API Client and is provided AS IS with no warranty whatsoever.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>

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
};

} // namespace KnishIO
