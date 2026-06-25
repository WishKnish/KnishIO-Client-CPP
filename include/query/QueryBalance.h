#pragma once

#include "query/Query.h"
#include <optional>  // std::optional/std::nullopt in the method signatures — not transitively included on Linux (cycle 127)
#include <string>

namespace knishio {
namespace query {

/**
 * Query for retrieving wallet balance information
 * 
 * Following the JS SDK pattern, this query retrieves balance information
 * for a specific wallet address, bundle hash, or token.
 */
class QueryBalance : public Query {
public:
    /**
     * GraphQL query string for balance retrieval
     * Matches the format from JS SDK QueryBalance.js
     */
    static constexpr const char* BALANCE_QUERY = R"(
query( $address: String, $bundleHash: String, $type: String, $token: String, $position: String ) {
    Balance( address: $address, bundleHash: $bundleHash, type: $type, token: $token, position: $position ) {
        address,
        bundleHash,
        type,
        tokenSlug,
        batchId,
        position,
        amount,
        characters,
        pubkey,
        createdAt,
        tokenUnits {
            id,
            name,
            metas
        },
        tradeRates {
            tokenSlug,
            amount
        }
    }
})";

    /**
     * Constructor
     * @param client The GraphQL client to use for execution
     */
    explicit QueryBalance(http::GraphQLClient* client);
    
    /**
     * Execute the balance query
     * @param address Optional wallet address
     * @param bundleHash Optional bundle hash
     * @param token Optional token slug
     * @param position Optional position
     * @param type Optional wallet type
     * @return JSON response containing balance information
     */
    nlohmann::json execute(
        const std::optional<std::string>& address = std::nullopt,
        const std::optional<std::string>& bundleHash = std::nullopt,
        const std::optional<std::string>& token = std::nullopt,
        const std::optional<std::string>& position = std::nullopt,
        const std::optional<std::string>& type = std::nullopt
    );
    
    /**
     * Execute with pre-built variables
     * @param variables The query variables
     * @return JSON response
     */
    nlohmann::json execute(const nlohmann::json& variables) override;
    
    /**
     * Create a ResponseBalance from JSON data
     * @param data The JSON response data
     * @return ResponseBalance object
     */
    std::unique_ptr<response::Response> createResponse(const nlohmann::json& data) override;
    
protected:
    /**
     * Build variables JSON from parameters
     * @param address Optional wallet address
     * @param bundleHash Optional bundle hash
     * @param token Optional token slug
     * @param position Optional position
     * @param type Optional wallet type
     * @return JSON object with variables
     */
    nlohmann::json buildVariables(
        const std::optional<std::string>& address,
        const std::optional<std::string>& bundleHash,
        const std::optional<std::string>& token,
        const std::optional<std::string>& position,
        const std::optional<std::string>& type
    );
};

} // namespace query
} // namespace knishio