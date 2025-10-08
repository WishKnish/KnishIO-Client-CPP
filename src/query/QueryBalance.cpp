#include "query/QueryBalance.h"
#include "response/Response.h"

namespace knishio {
namespace query {

QueryBalance::QueryBalance(http::GraphQLClient* client)
    : Query(client, BALANCE_QUERY) {
}

nlohmann::json QueryBalance::execute(
    const std::optional<std::string>& address,
    const std::optional<std::string>& bundleHash,
    const std::optional<std::string>& token,
    const std::optional<std::string>& position,
    const std::optional<std::string>& type) {
    
    nlohmann::json variables = buildVariables(address, bundleHash, token, position, type);
    return Query::execute(variables);
}

nlohmann::json QueryBalance::execute(const nlohmann::json& variables) {
    return Query::execute(variables);
}

std::unique_ptr<response::Response> QueryBalance::createResponse(const nlohmann::json& data) {
    // Create a ResponseBalance and populate it
    auto response = std::make_unique<response::ResponseBalance>();
    response->setData(data);
    
    // Parse the balance data if present
    if (data.contains("data") && data["data"].contains("Balance")) {
        response->parseData();
    }
    
    return response;
}

nlohmann::json QueryBalance::buildVariables(
    const std::optional<std::string>& address,
    const std::optional<std::string>& bundleHash,
    const std::optional<std::string>& token,
    const std::optional<std::string>& position,
    const std::optional<std::string>& type) {
    
    nlohmann::json variables;
    
    if (address.has_value()) {
        variables["address"] = address.value();
    }
    if (bundleHash.has_value()) {
        variables["bundleHash"] = bundleHash.value();
    }
    if (token.has_value()) {
        variables["token"] = token.value();
    }
    if (position.has_value()) {
        variables["position"] = position.value();
    }
    if (type.has_value()) {
        variables["type"] = type.value();
    }
    
    return variables;
}

} // namespace query
} // namespace knishio