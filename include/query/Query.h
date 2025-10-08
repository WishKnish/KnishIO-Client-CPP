#pragma once

#include <string>
#include <memory>
#include <future>
#include "third_party/nlohmann/json.hpp"

namespace knishio {

// Forward declarations
namespace http {
    class GraphQLClient;
}

namespace response {
    class Response;
}

namespace query {

/**
 * Base class for GraphQL queries
 * 
 * Following the JS/Kotlin SDK patterns, this is a simple base class
 * that stores the query string and variables, and handles execution.
 */
class Query {
public:
    /**
     * Constructor
     * @param client The GraphQL client to use for execution
     * @param queryString The GraphQL query string
     */
    Query(http::GraphQLClient* client, const std::string& queryString);
    
    /**
     * Destructor
     */
    virtual ~Query() = default;
    
    /**
     * Execute the query
     * @param variables Optional variables for the query
     * @return JSON response from the server
     */
    virtual nlohmann::json execute(const nlohmann::json& variables = {});
    
    /**
     * Execute the query asynchronously
     * @param variables Optional variables for the query
     * @return Future containing the JSON response
     */
    virtual std::future<nlohmann::json> executeAsync(const nlohmann::json& variables = {});
    
    /**
     * Create a response object from JSON data
     * @param data The JSON response data
     * @return Response object
     * @note Derived classes should override this to return specific response types
     */
    virtual std::unique_ptr<response::Response> createResponse(const nlohmann::json& data);
    
    /**
     * Get the query string
     * @return The GraphQL query string
     */
    [[nodiscard]] const std::string& getQueryString() const noexcept {
        return queryString_;
    }
    
    /**
     * Get the last used variables
     * @return The variables used in the last execution
     */
    [[nodiscard]] const nlohmann::json& getVariables() const noexcept {
        return variables_;
    }
    
protected:
    http::GraphQLClient* client_;       ///< GraphQL client (non-owning)
    std::string queryString_;            ///< GraphQL query string
    nlohmann::json variables_;           ///< Query variables
    nlohmann::json lastResponse_;        ///< Last response received
};

} // namespace query
} // namespace knishio