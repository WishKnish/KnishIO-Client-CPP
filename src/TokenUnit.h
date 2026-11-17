// Copyright 2019 WishKnish Corp. All rights reserved.
// You may use, distribute, and modify this code under the GPLV3 license, which is provided at:
// https://github.com/WishKnish/KnishIO-Client-JS/blob/master/LICENSE
// This experimental code is part of the Knish.IO API Client and is provided AS IS with no warranty whatsoever.

#pragma once

#include <string>
#include <vector>

#include "third_party/nlohmann/json.hpp"

namespace KnishIO {

/**
 * A single stackable (NFT) token unit. The canonical cross-SDK wire form is the JSON triple
 * [id, name, metas] (JS TokenUnit.toData()); a wallet's units serialize to
 * [[id, name, metas], ...] as the `tokenUnits` meta value on V-atoms.
 */
struct TokenUnit {
    std::string id;
    std::string name;
    // Any JSON value, object keys in document order. Null or another falsy value means {}.
    nlohmann::ordered_json metas = nlohmann::ordered_json::object();

    // JS TokenUnit.createFromGraphQL: string id/name; metas served as a non-empty JSON string are
    // parsed (invalid JSON throws nlohmann::json::parse_error, as JSON.parse throws SyntaxError);
    // absent or falsy metas, or a falsy parse result, become {}; any other value is kept.
    static TokenUnit fromGraphQL(const nlohmann::json &data);

    // JS toData(): [id, name, metas || {}] with every object in JS key order.
    [[nodiscard]] nlohmann::ordered_json toData() const;
};

// The units of a GraphQL wallet object's `tokenUnits` array ([] when absent).
std::vector<TokenUnit> tokenUnitsFromGraphQL(const nlohmann::json &wallet);

// JSON.stringify(units.map(unit => unit.toData())): the compact tokenUnits meta value.
std::string tokenUnitsJson(const std::vector<TokenUnit> &units);

// JSON.stringify key order, recursively: array-index keys ("0" to "4294967294", no leading zero)
// first in ascending numeric order, then the other keys in insertion order.
nlohmann::ordered_json jsKeyOrder(const nlohmann::ordered_json &value);

} // namespace KnishIO
