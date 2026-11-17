// Copyright 2019 WishKnish Corp. All rights reserved.
// You may use, distribute, and modify this code under the GPLV3 license, which is provided at:
// https://github.com/WishKnish/KnishIO-Client-JS/blob/master/LICENSE
// This experimental code is part of the Knish.IO API Client and is provided AS IS with no warranty whatsoever.

#include "TokenUnit.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>

namespace KnishIO {

namespace {

// JavaScript truthiness of a JSON value.
bool truthy(const nlohmann::ordered_json &value)
{
    if (value.is_null()) {
        return false;
    }
    if (value.is_boolean()) {
        return value.get<bool>();
    }
    if (value.is_string()) {
        return !value.get_ref<const std::string &>().empty();
    }
    if (value.is_number()) {
        const double d = value.get<double>();
        return d != 0.0 && !std::isnan(d);
    }
    return true;   // objects and arrays, even empty ones
}

// An ECMAScript array index: a canonical decimal integer below 2^32 - 1.
bool arrayIndex(const std::string &key, std::uint64_t &index)
{
    if (key.empty() || key.size() > 10 || (key.size() > 1 && key[0] == '0')) {
        return false;
    }
    index = 0;
    for (const char c : key) {
        if (c < '0' || c > '9') {
            return false;
        }
        index = index * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return index < 4294967295ULL;
}

} // anonymous namespace

nlohmann::ordered_json jsKeyOrder(const nlohmann::ordered_json &value)
{
    if (value.is_array()) {
        nlohmann::ordered_json out = nlohmann::ordered_json::array();
        for (const auto &item : value) {
            out.push_back(jsKeyOrder(item));
        }
        return out;
    }
    if (!value.is_object()) {
        return value;
    }
    std::vector<std::pair<std::uint64_t, std::string>> indexKeys;
    std::vector<std::string> otherKeys;
    for (const auto &item : value.items()) {
        std::uint64_t index = 0;
        if (arrayIndex(item.key(), index)) {
            indexKeys.emplace_back(index, item.key());
        } else {
            otherKeys.push_back(item.key());
        }
    }
    std::sort(indexKeys.begin(), indexKeys.end());
    nlohmann::ordered_json out = nlohmann::ordered_json::object();
    for (const auto &entry : indexKeys) {
        out[entry.second] = jsKeyOrder(value.at(entry.second));
    }
    for (const auto &key : otherKeys) {
        out[key] = jsKeyOrder(value.at(key));
    }
    return out;
}

TokenUnit TokenUnit::fromGraphQL(const nlohmann::json &data)
{
    TokenUnit unit;
    if (data.contains("id") && data["id"].is_string()) {
        unit.id = data["id"].get<std::string>();
    }
    if (data.contains("name") && data["name"].is_string()) {
        unit.name = data["name"].get<std::string>();
    }
    const auto served = data.find("metas");
    nlohmann::ordered_json metas = served == data.end() ? nlohmann::ordered_json() : nlohmann::ordered_json(*served);
    if (metas.is_string() && truthy(metas)) {
        metas = nlohmann::ordered_json::parse(metas.get_ref<const std::string &>());
    }
    unit.metas = truthy(metas) ? std::move(metas) : nlohmann::ordered_json::object();
    return unit;
}

nlohmann::ordered_json TokenUnit::toData() const
{
    return nlohmann::ordered_json::array({id, name, truthy(metas) ? jsKeyOrder(metas) : nlohmann::ordered_json::object()});
}

std::vector<TokenUnit> tokenUnitsFromGraphQL(const nlohmann::json &wallet)
{
    std::vector<TokenUnit> units;
    const auto served = wallet.find("tokenUnits");
    if (served != wallet.end() && served->is_array()) {
        for (const auto &unit : *served) {
            units.push_back(TokenUnit::fromGraphQL(unit));
        }
    }
    return units;
}

std::string tokenUnitsJson(const std::vector<TokenUnit> &units)
{
    nlohmann::ordered_json out = nlohmann::ordered_json::array();
    for (const auto &unit : units) {
        out.push_back(unit.toData());
    }
    return out.dump();
}

} // namespace KnishIO
