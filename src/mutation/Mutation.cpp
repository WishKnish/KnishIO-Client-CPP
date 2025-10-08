#include "mutation/Mutation.h"
#include "http/GraphQLClient.h"
#include "exception/KnishIOException.h"

namespace knishio {
namespace mutation {

Mutation::Mutation(http::GraphQLClient* client, const std::string& mutationString)
    : Query(client, mutationString) {
    // Mutation uses the same base implementation as Query
}

nlohmann::json Mutation::execute(const nlohmann::json& variables) {
    variables_ = variables;
    
    // Create the GraphQL request
    http::GraphQLClient::Request request;
    request.query = queryString_;  // GraphQL uses "query" field for both queries and mutations
    request.variables = variables_;
    
    // Execute as mutation
    auto responseFuture = client_->mutate(queryString_, variables_);
    auto response = responseFuture.get();
    
    if (!response.isSuccess()) {
        std::string errorMsg = "Mutation execution failed";
        if (response.error.has_value()) {
            errorMsg += ": " + response.error.value();
        }
        throw NetworkException(errorMsg, response.statusCode);
    }
    
    // Parse response body as JSON
    try {
        lastResponse_ = nlohmann::json::parse(response.body);
        return lastResponse_;
    } catch (const nlohmann::json::exception& e) {
        throw KnishIOException("Failed to parse response as JSON: " + std::string(e.what()));
    }
}

std::future<nlohmann::json> Mutation::executeAsync(const nlohmann::json& variables) {
    return std::async(std::launch::async, [this, variables]() {
        return execute(variables);
    });
}

} // namespace mutation
} // namespace knishio