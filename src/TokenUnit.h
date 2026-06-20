// Copyright 2019 WishKnish Corp. All rights reserved.
// You may use, distribute, and modify this code under the GPLV3 license, which is provided at:
// https://github.com/WishKnish/KnishIO-Client-JS/blob/master/LICENSE
// This experimental code is part of the Knish.IO API Client and is provided AS IS with no warranty whatsoever.

#pragma once

#include <string>
#include <map>

namespace KnishIO {

/**
 * A single stackable (NFT) token unit. The canonical cross-SDK wire form is the JSON triple
 * [id, name, metas] (matches JS/Rust/Python to_data()); a wallet's units serialize to
 * [[id, name, metas], ...] as the `tokenUnits` meta value on V-atoms.
 */
struct TokenUnit {
    std::string id;
    std::string name;
    std::map<std::string, std::string> metas;
};

} // namespace KnishIO
