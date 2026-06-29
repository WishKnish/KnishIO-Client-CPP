#pragma once

#include <string>
#include <memory>
#include <chrono>
#include <future>
#include <optional>
#include <unordered_map>
#include <curl/curl.h>
#include "third_party/nlohmann/json.hpp"

// PQ-transport (Phase E): the AUTH source wallet that en/decrypts the ML-KEM CipherHash envelope.
namespace KnishIO { class Wallet; }

namespace knishio {
namespace http {

/**
 * HTTP client for GraphQL communication with Knish.IO nodes
 * 
 * This class provides a thread-safe, asynchronous interface for
 * sending GraphQL queries and mutations to distributed ledger nodes.
 * It handles retry logic, load balancing, and response parsing.
 * 
 * @note Uses libcurl for HTTP communication and JsonCpp for JSON parsing
 */
class GraphQLClient {
public:
    /**
     * HTTP response structure
     */
    struct Response {
        int statusCode;                                    ///< HTTP status code
        std::string body;                                  ///< Response body
        std::unordered_map<std::string, std::string> headers; ///< Response headers
        std::optional<std::string> error;                  ///< Error message if failed
        
        [[nodiscard]] bool isSuccess() const noexcept {
            return statusCode >= 200 && statusCode < 300;
        }
        
        [[nodiscard]] nlohmann::json toJson() const;
    };
    
    /**
     * GraphQL request structure
     */
    struct Request {
        std::string query;                                 ///< GraphQL query string
        std::optional<nlohmann::json> variables;           ///< Query variables
        std::optional<std::string> operationName;          ///< Operation name
        
        [[nodiscard]] std::string toJsonString() const;
    };
    
    /**
     * Configuration for retry behavior
     */
    struct RetryConfig {
        int maxRetries = 3;                               ///< Maximum retry attempts
        std::chrono::milliseconds initialDelay{1000};     ///< Initial retry delay
        double backoffMultiplier = 2.0;                   ///< Exponential backoff multiplier
        std::chrono::milliseconds maxDelay{30000};        ///< Maximum retry delay
    };
    
    /**
     * Constructor
     * @param uri The GraphQL endpoint URI
     * @param timeout Timeout in milliseconds for requests
     * @param maxRetries Maximum number of retry attempts
     */
    GraphQLClient(const std::string& uri, 
                  long timeout = 30000,
                  int maxRetries = 3);
    
    /**
     * Destructor - cleanup CURL resources
     */
    ~GraphQLClient();
    
    // Delete copy operations (CURL handles are not copyable)
    GraphQLClient(const GraphQLClient&) = delete;
    GraphQLClient& operator=(const GraphQLClient&) = delete;
    
    // Allow move operations
    GraphQLClient(GraphQLClient&&) noexcept;
    GraphQLClient& operator=(GraphQLClient&&) noexcept;
    
    /**
     * Execute a GraphQL query
     * @param query The GraphQL query string
     * @param variables Optional query variables
     * @return Future containing the response
     */
    [[nodiscard]] std::future<Response> query(
        const std::string& query,
        const std::optional<nlohmann::json>& variables = std::nullopt);
    
    /**
     * Execute a GraphQL mutation
     * @param mutation The GraphQL mutation string
     * @param variables Optional mutation variables
     * @return Future containing the response
     */
    [[nodiscard]] std::future<Response> mutate(
        const std::string& mutation,
        const std::optional<nlohmann::json>& variables = std::nullopt);
    
    /**
     * Execute a raw GraphQL request
     * @param request The request to execute
     * @return Future containing the response
     */
    [[nodiscard]] std::future<Response> execute(const Request& request);
    
    /**
     * Set authorization token
     * @param token The authorization token
     */
    void setAuthToken(const std::string& token);
    
    /**
     * Clear authorization token
     */
    void clearAuthToken();

    /**
     * PQ-transport (Phase E): toggle the ML-KEM CipherHash encrypted transport.
     * @param encrypt True to wrap requests in CipherHash + decrypt responses.
     */
    void setEncryption(bool encrypt);

    /**
     * PQ-transport (Phase E): supply the decrypting wallet (the AUTH source wallet) + the
     * validator's advertised ML-KEM public key (base64). Set once at auth.
     */
    void setCipherContext(std::shared_ptr<KnishIO::Wallet> wallet, const std::string& serverPubKey);
    
    /**
     * Set custom header
     * @param name Header name
     * @param value Header value
     */
    void setHeader(const std::string& name, const std::string& value);
    
    /**
     * Remove custom header
     * @param name Header name to remove
     */
    void removeHeader(const std::string& name);
    
    /**
     * Get the current URI
     * @return The GraphQL endpoint URI
     */
    [[nodiscard]] std::string getUri() const;
    
    /**
     * Set a new URI
     * @param uri The new GraphQL endpoint URI
     */
    void setUri(const std::string& uri);
    
    /**
     * Set retry configuration
     * @param config The retry configuration
     */
    void setRetryConfig(const RetryConfig& config);
    
    /**
     * Enable or disable verbose logging
     * @param enable True to enable verbose logging
     */
    void setVerbose(bool enable);

    /**
     * Enable or disable TLS certificate verification (disable for self-signed dev validators)
     * @param verify True (default) verifies the peer + host; false skips verification
     */
    void setVerifySSL(bool verify);

    /**
     * Check if the client is connected (last request succeeded)
     * @return True if the last request succeeded
     */
    [[nodiscard]] bool isConnected() const noexcept;
    
    /**
     * Get statistics about requests
     * @return Map of statistics (total_requests, failed_requests, etc.)
     */
    [[nodiscard]] std::unordered_map<std::string, size_t> getStats() const;
    
private:
    // Private implementation (pImpl idiom)
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    // Internal methods
    [[nodiscard]] Response executeInternal(const Request& request);
    [[nodiscard]] Response executeWithRetry(const Request& request);
    
    // CURL callback functions
    static size_t writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata);
    static size_t headerCallback(char* buffer, size_t size, size_t nitems, void* userdata);
    
    void initializeCurl();
    void cleanupCurl();
    void setupRequestHeaders(CURL* curl, const Request& request);
    [[nodiscard]] Response parseCurlResponse(CURL* curl, const std::string& responseBody,
                                            const std::unordered_map<std::string, std::string>& headers);
};

/**
 * Exception thrown for GraphQL-specific errors
 */
class GraphQLException : public std::runtime_error {
public:
    explicit GraphQLException(const std::string& message)
        : std::runtime_error("GraphQL Error: " + message) {}
    
    GraphQLException(const std::string& message, int httpStatus)
        : std::runtime_error("GraphQL Error (HTTP " + std::to_string(httpStatus) + "): " + message),
          httpStatus_(httpStatus) {}
    
    [[nodiscard]] std::optional<int> getHttpStatus() const noexcept {
        return httpStatus_;
    }
    
private:
    std::optional<int> httpStatus_;
};

} // namespace http
} // namespace knishio