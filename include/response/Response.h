#pragma once

#include <string>
#include <optional>
#include <memory>
#include <vector>
#include <unordered_map>
#include "third_party/nlohmann/json.hpp"

namespace knishio {
namespace response {

/**
 * Base class for all GraphQL responses
 */
class Response {
public:
    Response() = default;
    virtual ~Response() = default;
    
    /**
     * Check if the response was successful
     * @return true if successful, false otherwise
     */
    [[nodiscard]] virtual bool isSuccess() const noexcept {
        return !error.has_value();
    }
    
    /**
     * Get the raw JSON data
     * @return The JSON data
     */
    [[nodiscard]] nlohmann::json getData() const {
        return data;
    }
    
    /**
     * Set the response data
     * @param json The JSON response data
     */
    void setData(const nlohmann::json& json) {
        data = json;
    }
    
    /**
     * Get error message if any
     * @return Error message or nullopt
     */
    [[nodiscard]] std::optional<std::string> getError() const {
        return error;
    }
    
    /**
     * Set error message
     * @param errorMsg The error message
     */
    void setError(const std::string& errorMsg) {
        error = errorMsg;
    }
    
protected:
    nlohmann::json data;                      ///< Raw response data
    std::optional<std::string> error;         ///< Error message if any
};

/**
 * Response for balance queries
 */
class ResponseBalance : public Response {
public:
    struct Balance {
        std::string address;
        std::string bundleHash;
        std::string tokenSlug;
        std::string amount;
        std::string position;
        std::string batchId;
        std::vector<std::string> characters;
    };
    
    /**
     * Get the balance information
     * @return Balance structure or nullptr if not available
     */
    [[nodiscard]] std::optional<Balance> getBalance() const;
    
    /**
     * Parse response data into balance structure
     */
    void parseData();
    
private:
    std::optional<Balance> balance;
};

/**
 * Response for wallet list queries
 */
class ResponseWalletList : public Response {
public:
    struct Wallet {
        std::string address;
        std::string bundleHash;
        std::string token;
        std::string position;
        std::string pubkey;
        std::string balance;
    };
    
    /**
     * Get the list of wallets
     * @return Vector of wallet structures
     */
    [[nodiscard]] std::vector<Wallet> getWallets() const {
        return wallets;
    }
    
    /**
     * Parse response data into wallet list
     */
    void parseData();
    
private:
    std::vector<Wallet> wallets;
};

/**
 * Response for ContinuID queries
 */
class ResponseContinuId : public Response {
public:
    struct ContinuID {
        std::string bundle;
        std::string position;
        std::string walletAddress;
        std::string timestamp;
    };
    
    /**
     * Get the ContinuID information
     * @return ContinuID structure or nullptr if not available
     */
    [[nodiscard]] std::optional<ContinuID> getContinuId() const {
        return continuId;
    }
    
    /**
     * Parse response data into ContinuID structure
     */
    void parseData();
    
private:
    std::optional<ContinuID> continuId;
};

/**
 * Response for token creation
 */
class ResponseCreateToken : public Response {
public:
    /**
     * Check if token was created successfully
     * @return true if created, false otherwise
     */
    [[nodiscard]] bool isCreated() const;
    
    /**
     * Get the created token slug
     * @return Token slug
     */
    [[nodiscard]] std::string getTokenSlug() const;
    
    /**
     * Get the initial amount
     * @return Initial token amount
     */
    [[nodiscard]] std::string getAmount() const;
};

/**
 * Response for token transfers
 */
class ResponseTransferTokens : public Response {
public:
    /**
     * Check if transfer was successful
     * @return true if successful, false otherwise
     */
    [[nodiscard]] bool isTransferred() const;
    
    /**
     * Get the transaction hash
     * @return Transaction hash
     */
    [[nodiscard]] std::string getTransactionHash() const;
    
    /**
     * Get the transferred amount
     * @return Amount transferred
     */
    [[nodiscard]] std::string getAmount() const;
};

/**
 * Response for authorization requests
 */
class ResponseRequestAuthorization : public Response {
public:
    /**
     * Get the authorization token
     * @return Auth token or empty string
     */
    [[nodiscard]] std::string getAuthToken() const;
    
    /**
     * Get the public key
     * @return Public key
     */
    [[nodiscard]] std::string getPublicKey() const;
    
    /**
     * Check if authorized successfully
     * @return true if authorized, false otherwise
     */
    [[nodiscard]] bool isAuthorized() const;
};

/**
 * Response for molecule proposals
 */
class ResponseProposeMolecule : public Response {
public:
    /**
     * Get the molecular hash
     * @return Molecular hash
     */
    [[nodiscard]] std::string getMolecularHash() const;
    
    /**
     * Get the molecule status
     * @return Status string
     */
    [[nodiscard]] std::string getStatus() const;
    
    /**
     * Check if molecule was accepted
     * @return true if accepted, false otherwise
     */
    [[nodiscard]] bool isAccepted() const;
    
    /**
     * Get any rejection reason
     * @return Rejection reason or empty string
     */
    [[nodiscard]] std::string getRejectionReason() const;
};

} // namespace response
} // namespace knishio