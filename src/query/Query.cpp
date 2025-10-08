#include "query/Query.h"
#include "http/GraphQLClient.h"
#include "response/Response.h"
#include "exception/KnishIOException.h"
#include <thread>

namespace knishio {
namespace query {

Query::Query(http::GraphQLClient* client, const std::string& queryString)
    : client_(client), queryString_(queryString) {
    if (!client_) {
        throw KnishIOException("Query: GraphQL client cannot be null");
    }
    if (queryString_.empty()) {
        throw KnishIOException("Query: Query string cannot be empty");
    }
}

nlohmann::json Query::execute(const nlohmann::json& variables) {
    variables_ = variables;
    
    // Create the GraphQL request
    http::GraphQLClient::Request request;
    request.query = queryString_;
    request.variables = variables_;
    
    // Execute synchronously
    auto responseFuture = client_->execute(request);
    auto response = responseFuture.get();
    
    if (!response.isSuccess()) {
        std::string errorMsg = "Query execution failed";
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

std::future<nlohmann::json> Query::executeAsync(const nlohmann::json& variables) {
    return std::async(std::launch::async, [this, variables]() {
        return execute(variables);
    });
}

std::unique_ptr<response::Response> Query::createResponse(const nlohmann::json& data) {
    // Base implementation creates a generic Response
    auto response = std::make_unique<response::Response>();
    response->setData(data);
    return response;
}

} // namespace query
} // namespace knishio