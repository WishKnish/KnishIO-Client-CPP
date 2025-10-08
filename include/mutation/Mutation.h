#pragma once

#include "query/Query.h"

namespace knishio {
namespace mutation {

/**
 * Base class for GraphQL mutations
 * 
 * Following the JS SDK pattern, Mutation is a simple extension of Query
 * that changes the operation type from "query" to "mutation"
 */
class Mutation : public query::Query {
public:
    /**
     * Constructor
     * @param client The GraphQL client to use for execution
     * @param mutationString The GraphQL mutation string
     */
    Mutation(http::GraphQLClient* client, const std::string& mutationString);
    
    /**
     * Execute the mutation
     * @param variables Optional variables for the mutation
     * @return JSON response from the server
     * @note Overrides Query::execute to use mutation semantics
     */
    nlohmann::json execute(const nlohmann::json& variables = {}) override;
    
    /**
     * Execute the mutation asynchronously
     * @param variables Optional variables for the mutation
     * @return Future containing the JSON response
     */
    std::future<nlohmann::json> executeAsync(const nlohmann::json& variables = {}) override;
};

} // namespace mutation
} // namespace knishio