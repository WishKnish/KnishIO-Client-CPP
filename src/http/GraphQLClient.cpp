#include "http/GraphQLClient.h"
#include "exception/KnishIOException.h"
#include "third_party/nlohmann/json.hpp"
#include "Wallet.h"
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>
#include <regex>
#include <algorithm>
#include <sodium.h>

namespace knishio {
namespace http {

namespace {

// PQ-transport (Phase E): the canonical ML-KEM CipherHash transport query (matches the validator
// + the other SDKs).
const char* const CIPHER_HASH_QUERY =
    "query ( $Hash: String! ) { CipherHash ( Hash: $Hash ) { hash } }";

// Light parse of a GraphQL query → (operation_type, root_field_name), for the CipherHash bypass.
std::pair<std::string, std::string> parseOperation(const std::string& query) {
    std::string type = "query";
    std::smatch m;
    std::regex opRe(R"(\b(query|mutation|subscription)\b)", std::regex::icase);
    if (std::regex_search(query, m, opRe)) {
        type = m[1].str();
        std::transform(type.begin(), type.end(), type.begin(),
                       [](unsigned char c) { return static_cast<char>(::tolower(c)); });
    }
    std::string name;
    auto brace = query.find('{');
    if (brace != std::string::npos) {
        std::string rest = query.substr(brace + 1);
        std::smatch nm;
        std::regex idRe(R"([A-Za-z_][A-Za-z0-9_]*)");
        if (std::regex_search(rest, nm, idRe)) {
            name = nm[0].str();
        }
    }
    return {type, name};
}

// Whether an outgoing request should be wrapped in CipherHash. Bypass (plaintext): __schema/
// ContinuId queries, the AccessToken mutation, and the U-isotope ProposeMolecule (auth bootstrap —
// the key exchange itself can't be encrypted). Mirrors the validator/other-SDK bypass set.
bool shouldEncryptRequest(const GraphQLClient::Request& request) {
    auto op = parseOperation(request.query);
    const std::string& type = op.first;
    const std::string& name = op.second;
    if (type == "query" && (name == "__schema" || name == "ContinuId")) return false;
    if (type == "mutation" && name == "AccessToken") return false;
    if (type == "mutation" && name == "ProposeMolecule" && request.variables.has_value()) {
        const auto& v = request.variables.value();
        if (v.contains("molecule") && v["molecule"].contains("atoms")
            && v["molecule"]["atoms"].is_array() && !v["molecule"]["atoms"].empty()) {
            const auto& a0 = v["molecule"]["atoms"][0];
            if (a0.contains("isotope") && a0["isotope"].is_string()
                && a0["isotope"].get<std::string>() == "U") {
                return false;
            }
        }
    }
    return true;
}

} // anonymous namespace

// Implementation class
class GraphQLClient::Impl {
public:
    std::string uri;
    long timeout;
    RetryConfig retryConfig;
    std::optional<std::string> authToken;
    std::unordered_map<std::string, std::string> customHeaders;
    bool verbose = false;
    bool verifySSL = true;  /* false allows self-signed dev validators */

    // PQ-transport (Phase E): ML-KEM CipherHash encrypted transport state.
    bool cipherEnabled = false;
    std::optional<std::string> serverPubKey;        // validator's advertised ML-KEM pubkey (base64)
    std::shared_ptr<KnishIO::Wallet> cipherWallet;  // the AUTH source wallet that decrypts responses

    // Statistics
    mutable std::mutex statsMutex;
    std::atomic<size_t> totalRequests{0};
    std::atomic<size_t> failedRequests{0};
    std::atomic<size_t> retryCount{0};
    std::atomic<bool> lastRequestSucceeded{false};
    
    // CURL handle pool for thread safety
    mutable std::mutex curlMutex;
    std::vector<CURL*> curlHandles;
    
    Impl(const std::string& uri, long timeout, int maxRetries)
        : uri(uri), timeout(timeout) {
        retryConfig.maxRetries = maxRetries;
    }
    
    ~Impl() {
        // Clean up CURL handles
        std::lock_guard<std::mutex> lock(curlMutex);
        for (CURL* handle : curlHandles) {
            curl_easy_cleanup(handle);
        }
        curlHandles.clear();
    }
    
    CURL* getCurlHandle() {
        std::lock_guard<std::mutex> lock(curlMutex);
        if (!curlHandles.empty()) {
            CURL* handle = curlHandles.back();
            curlHandles.pop_back();
            curl_easy_reset(handle);
            return handle;
        }
        return curl_easy_init();
    }
    
    void returnCurlHandle(CURL* handle) {
        std::lock_guard<std::mutex> lock(curlMutex);
        curlHandles.push_back(handle);
    }
};

// Response methods
nlohmann::json GraphQLClient::Response::toJson() const {
    if (body.empty()) {
        return nlohmann::json();
    }
    
    try {
        return nlohmann::json::parse(body);
    } catch (const nlohmann::json::parse_error& e) {
        throw GraphQLException("Failed to parse JSON response: " + std::string(e.what()));
    }
}

// Request methods
std::string GraphQLClient::Request::toJsonString() const {
    nlohmann::json root;
    root["query"] = query;
    
    if (variables.has_value()) {
        root["variables"] = variables.value();
    }
    
    if (operationName.has_value()) {
        root["operationName"] = operationName.value();
    }
    
    return root.dump();
}

// Main class implementation
GraphQLClient::GraphQLClient(const std::string& uri, long timeout, int maxRetries)
    : pImpl_(std::make_unique<Impl>(uri, timeout, maxRetries)) {
    initializeCurl();
}

GraphQLClient::~GraphQLClient() {
    cleanupCurl();
}

// Move constructor
GraphQLClient::GraphQLClient(GraphQLClient&&) noexcept = default;

// Move assignment operator
GraphQLClient& GraphQLClient::operator=(GraphQLClient&&) noexcept = default;

void GraphQLClient::initializeCurl() {
    static std::once_flag initFlag;
    std::call_once(initFlag, []() {
        if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
            throw KnishIOException("Failed to initialize libcurl");
        }
    });
}

void GraphQLClient::cleanupCurl() {
    // Note: curl_global_cleanup() should only be called once at program exit
    // We don't call it here as other instances might still be using curl
}

std::future<GraphQLClient::Response> GraphQLClient::query(
    const std::string& query,
    const std::optional<nlohmann::json>& variables) {
    
    return std::async(std::launch::async, [this, query, variables]() {
        Request request;
        request.query = query;
        request.variables = variables;
        return executeWithRetry(request);
    });
}

std::future<GraphQLClient::Response> GraphQLClient::mutate(
    const std::string& mutation,
    const std::optional<nlohmann::json>& variables) {
    
    return std::async(std::launch::async, [this, mutation, variables]() {
        Request request;
        request.query = mutation;
        request.variables = variables;
        return executeWithRetry(request);
    });
}

std::future<GraphQLClient::Response> GraphQLClient::execute(const Request& request) {
    return std::async(std::launch::async, [this, request]() {
        return executeWithRetry(request);
    });
}

GraphQLClient::Response GraphQLClient::executeWithRetry(const Request& request) {
    Response lastResponse;
    auto delay = pImpl_->retryConfig.initialDelay;
    
    for (int attempt = 0; attempt <= pImpl_->retryConfig.maxRetries; ++attempt) {
        if (attempt > 0) {
            // Wait before retry
            std::this_thread::sleep_for(delay);
            
            // Update delay for next retry (exponential backoff)
            delay = std::chrono::milliseconds(
                static_cast<long>(delay.count() * pImpl_->retryConfig.backoffMultiplier)
            );
            
            if (delay > pImpl_->retryConfig.maxDelay) {
                delay = pImpl_->retryConfig.maxDelay;
            }
            
            pImpl_->retryCount++;
        }
        
        try {
            lastResponse = executeInternal(request);
            
            if (lastResponse.isSuccess()) {
                pImpl_->lastRequestSucceeded = true;
                return lastResponse;
            }
            
            // Don't retry on client errors (4xx)
            if (lastResponse.statusCode >= 400 && lastResponse.statusCode < 500) {
                pImpl_->failedRequests++;
                pImpl_->lastRequestSucceeded = false;
                return lastResponse;
            }
            
        } catch (const std::exception& e) {
            lastResponse.error = e.what();
            lastResponse.statusCode = 0;
        }
    }
    
    pImpl_->failedRequests++;
    pImpl_->lastRequestSucceeded = false;
    
    if (!lastResponse.error.has_value()) {
        lastResponse.error = "Request failed after " + 
                            std::to_string(pImpl_->retryConfig.maxRetries) + " retries";
    }
    
    return lastResponse;
}

// CURL callbacks
size_t GraphQLClient::writeCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* response = static_cast<std::string*>(userdata);
    size_t totalSize = size * nmemb;
    response->append(ptr, totalSize);
    return totalSize;
}

size_t GraphQLClient::headerCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* headers = static_cast<std::unordered_map<std::string, std::string>*>(userdata);
    size_t totalSize = size * nitems;
    
    std::string header(buffer, totalSize);
    size_t colonPos = header.find(':');
    
    if (colonPos != std::string::npos) {
        std::string name = header.substr(0, colonPos);
        std::string value = header.substr(colonPos + 1);
        
        // Trim whitespace
        value.erase(0, value.find_first_not_of(" \t\r\n"));
        value.erase(value.find_last_not_of(" \t\r\n") + 1);
        
        (*headers)[name] = value;
    }
    
    return totalSize;
}

void GraphQLClient::setupRequestHeaders(CURL* curl, const Request& request) {
    struct curl_slist* headers = nullptr;
    
    // Add content type
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    
    // Add authorization token if present (the validator reads the X-Auth-Token header,
    // not Authorization: Bearer — matches the JS/TS/all-SDK convention).
    if (pImpl_->authToken.has_value()) {
        std::string authHeader = "X-Auth-Token: " + pImpl_->authToken.value();
        headers = curl_slist_append(headers, authHeader.c_str());
    }
    
    // Add custom headers
    for (const auto& [name, value] : pImpl_->customHeaders) {
        std::string header = name;
        header += ": ";
        header += value;
        headers = curl_slist_append(headers, header.c_str());
    }
    
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
}

GraphQLClient::Response GraphQLClient::executeInternal(const Request& request) {
    pImpl_->totalRequests++;
    
    CURL* curl = pImpl_->getCurlHandle();
    if (!curl) {
        throw GraphQLException("Failed to initialize CURL handle");
    }
    
    // Ensure curl handle is returned to pool
    auto curlCleanup = [this](CURL* handle) {
        pImpl_->returnCurlHandle(handle);
    };
    std::unique_ptr<CURL, decltype(curlCleanup)> curlGuard(curl, curlCleanup);
    
    Response response;
    std::string responseBody;
    std::unordered_map<std::string, std::string> responseHeaders;
    
    // Set URL
    curl_easy_setopt(curl, CURLOPT_URL, pImpl_->uri.c_str());
    
    // Set POST data — PQ-transport Phase E: wrap in the ML-KEM CipherHash envelope when encryption
    // is enabled and the operation isn't bypassed (the validator decrypts it). Encrypt the FULL
    // body string (the validator recovers it as a JSON string value → parses the inner request).
    bool encryptedRequest = false;
    std::string postData;
    if (pImpl_->cipherEnabled && pImpl_->cipherWallet && pImpl_->serverPubKey.has_value()
        && shouldEncryptRequest(request)) {
        std::string envelope = pImpl_->cipherWallet->encryptStringML768(
            request.toJsonString(), pImpl_->serverPubKey.value());
        Request wrapped;
        wrapped.query = CIPHER_HASH_QUERY;
        wrapped.variables = nlohmann::json{{"Hash", envelope}};
        postData = wrapped.toJsonString();
        encryptedRequest = true;
    } else {
        postData = request.toJsonString();
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, postData.length());
    
    // Set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, headerCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
    
    // Set timeout
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, pImpl_->timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, pImpl_->timeout / 3);
    
    // Set verbose mode
    curl_easy_setopt(curl, CURLOPT_VERBOSE, pImpl_->verbose ? 1L : 0L);
    
    // Enable HTTP/2
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    
    // Follow redirects (max 3)
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    
    // SSL/TLS options (verifySSL=false allows self-signed dev validators)
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, pImpl_->verifySSL ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, pImpl_->verifySSL ? 2L : 0L);
    
    // Set headers
    setupRequestHeaders(curl, request);
    
    // Perform request
    CURLcode res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        response.statusCode = 0;
        response.error = "CURL error: " + std::string(curl_easy_strerror(res));
        return response;
    }
    
    // Get HTTP status code
    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    response.statusCode = static_cast<int>(httpCode);
    response.body = responseBody;
    response.headers = responseHeaders;

    // PQ-transport Phase E: decrypt the CipherHash response envelope back to the inner GraphQL
    // response JSON (which replaces the body for normal parsing). The validator encrypts the
    // response OBJECT, so decryptMyMessageML768 returns the raw inner JSON (no JSON-decode).
    if (encryptedRequest && pImpl_->cipherWallet) {
        try {
            nlohmann::json env = nlohmann::json::parse(response.body);
            if (env.contains("data") && env["data"].is_object()
                && env["data"].contains("CipherHash") && env["data"]["CipherHash"].is_object()
                && env["data"]["CipherHash"].contains("hash")
                && env["data"]["CipherHash"]["hash"].is_string()) {
                std::string decrypted = pImpl_->cipherWallet->decryptMyMessageML768(
                    env["data"]["CipherHash"]["hash"].get<std::string>());
                if (!decrypted.empty()) {
                    response.body = decrypted;
                }
            }
        } catch (const std::exception&) {
            // Not a CipherHash envelope (e.g. a plaintext error response) — leave body unchanged.
        }
    }

    // Check for GraphQL errors in response
    try {
        nlohmann::json jsonResponse = response.toJson();
        if (jsonResponse.contains("errors") && jsonResponse["errors"].is_array()) {
            response.error = jsonResponse["errors"].dump();
        }
    } catch (const std::exception&) {
        // Ignore JSON parsing errors here - the body might not be JSON
    }
    
    return response;
}

void GraphQLClient::setAuthToken(const std::string& token) {
    pImpl_->authToken = token;
}

void GraphQLClient::setEncryption(bool encrypt) {
    pImpl_->cipherEnabled = encrypt;
}

void GraphQLClient::setCipherContext(std::shared_ptr<KnishIO::Wallet> wallet, const std::string& serverPubKey) {
    pImpl_->cipherWallet = std::move(wallet);
    pImpl_->serverPubKey = serverPubKey;
}

void GraphQLClient::clearAuthToken() {
    if (pImpl_->authToken.has_value()) {
        // Securely clear the token
        sodium_memzero(const_cast<char*>(pImpl_->authToken->data()), 
                      pImpl_->authToken->size());
        pImpl_->authToken.reset();
    }
}

void GraphQLClient::setHeader(const std::string& name, const std::string& value) {
    pImpl_->customHeaders[name] = value;
}

void GraphQLClient::removeHeader(const std::string& name) {
    pImpl_->customHeaders.erase(name);
}

std::string GraphQLClient::getUri() const {
    return pImpl_->uri;
}

void GraphQLClient::setUri(const std::string& uri) {
    pImpl_->uri = uri;
}

void GraphQLClient::setRetryConfig(const RetryConfig& config) {
    pImpl_->retryConfig = config;
}

void GraphQLClient::setVerbose(bool enable) {
    pImpl_->verbose = enable;
}

void GraphQLClient::setVerifySSL(bool verify) {
    pImpl_->verifySSL = verify;
}

bool GraphQLClient::isConnected() const noexcept {
    return pImpl_->lastRequestSucceeded.load();
}

std::unordered_map<std::string, size_t> GraphQLClient::getStats() const {
    std::lock_guard<std::mutex> lock(pImpl_->statsMutex);
    return {
        {"total_requests", pImpl_->totalRequests.load()},
        {"failed_requests", pImpl_->failedRequests.load()},
        {"retry_count", pImpl_->retryCount.load()},
        {"success_rate", pImpl_->totalRequests > 0 
            ? (pImpl_->totalRequests - pImpl_->failedRequests) * 100 / pImpl_->totalRequests
            : 0}
    };
}

} // namespace http
} // namespace knishio