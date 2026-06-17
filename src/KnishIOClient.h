#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <future>
#include <optional>
#include <unordered_map>
#include <random>
#include <functional>

// Forward declarations for KnishIO namespace classes
namespace KnishIO {
    class Wallet;
    class Molecule;
}

namespace knishio {
    class AuthToken;
    
    namespace http {
        class GraphQLClient;
    }
    
    namespace response {
        class Response;
        class ResponseBalance;
        class ResponseWalletList;
        class ResponseContinuId;
        class ResponseCreateToken;
        class ResponseTransferTokens;
        class ResponseRequestAuthorization;
        class ResponseProposeMolecule;
    }
}

namespace knishio {

/**
 * Main client class for interacting with the Knish.IO distributed ledger
 * 
 * This class provides a high-level interface for common DLT operations,
 * including wallet management, token transfers, and molecular composition.
 * 
 * @example
 * auto client = KnishIOClient::Builder()
 *     .uris({"https://node1.knishio.com", "https://node2.knishio.com"})
 *     .cellSlug("my-cell")
 *     .enableLogging()
 *     .build();
 */
class KnishIOClient {
public:
    /**
     * Configuration structure for KnishIOClient
     */
    struct Config {
        std::vector<std::string> uris;                    ///< List of node URIs for load balancing
        std::optional<std::string> cellSlug;              ///< Optional cell identifier
        int serverSdkVersion = 3;                         ///< Server SDK version compatibility
        bool logging = false;                             ///< Enable debug logging
        bool encrypt = false;                             ///< Enable encryption for communications
        bool insecureTls = false;                         ///< Skip TLS cert verification (dev/self-signed validators)
        std::chrono::milliseconds timeout{30000};         ///< Request timeout
        int maxRetries = 3;                              ///< Maximum retry attempts
        std::chrono::milliseconds retryDelay{1000};      ///< Delay between retries
    };

    /**
     * Builder pattern for creating KnishIOClient instances
     */
    class Builder {
    public:
        Builder& uris(const std::vector<std::string>& uris);
        Builder& cellSlug(const std::string& cellSlug);
        Builder& serverSdkVersion(int version);
        Builder& enableLogging(bool enable = true);
        Builder& enableEncryption(bool enable = true);
        Builder& insecureTls(bool enable = true);
        Builder& timeout(std::chrono::milliseconds timeout);
        Builder& maxRetries(int retries);
        Builder& retryDelay(std::chrono::milliseconds delay);
        
        [[nodiscard]] std::unique_ptr<KnishIOClient> build() const;
        
    private:
        Config config_;
    };

    // Constructors and destructor
    explicit KnishIOClient(const Config& config);
    ~KnishIOClient();
    
    // Delete copy operations (non-copyable)
    KnishIOClient(const KnishIOClient&) = delete;
    KnishIOClient& operator=(const KnishIOClient&) = delete;
    
    // Allow move operations
    KnishIOClient(KnishIOClient&&) noexcept;
    KnishIOClient& operator=(KnishIOClient&&) noexcept;

    // Configuration management
    
    /**
     * Set the cell slug for cellular architecture operations
     * @param cellSlug The cell identifier
     */
    void setCellSlug(const std::string& cellSlug);
    
    /**
     * Get the current cell slug
     * @return The cell slug if set, std::nullopt otherwise
     */
    [[nodiscard]] std::optional<std::string> getCellSlug() const noexcept;
    
    /**
     * Set the secret for wallet operations
     * @param secret The hexadecimal secret string (typically 2048 characters)
     */
    void setSecret(const std::string& secret);
    
    /**
     * Check if a secret has been set
     * @return true if secret is set, false otherwise
     */
    [[nodiscard]] bool hasSecret() const noexcept;
    
    /**
     * Get the current bundle hash
     * @return The bundle hash
     */
    [[nodiscard]] std::string getBundle() const;

    // Wallet operations
    
    /**
     * Query the balance for a specific token
     * @param token The token slug
     * @param bundle Optional bundle hash filter
     * @return Future containing the balance response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseBalance>> 
    queryBalance(const std::string& token, 
                 const std::optional<std::string>& bundle = std::nullopt);
    
    /**
     * Query the list of wallets
     * @param bundle Optional bundle hash filter
     * @param token Optional token slug filter
     * @return Future containing the wallet list response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseWalletList>> 
    queryWallets(const std::optional<std::string>& bundle = std::nullopt,
                 const std::optional<std::string>& token = std::nullopt);
    
    /**
     * Query ContinuID for a bundle
     * @param bundle The bundle hash
     * @return Future containing the ContinuID response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseContinuId>> 
    queryContinuId(const std::string& bundle);

    // Molecule operations
    
    /**
     * Create a new molecule for transaction composition
     * @param secret Optional secret (uses client secret if not provided)
     * @param sourceWallet Optional source wallet (takes ownership if provided)
     * @param cellSlug Optional cell slug
     * @return The created molecule (caller takes ownership)
     * @note The returned pointer must be deleted by the caller or wrapped in a smart pointer
     */
    [[nodiscard]] KnishIO::Molecule* createMolecule(
        const std::optional<std::string>& secret = std::nullopt,
        KnishIO::Wallet* sourceWallet = nullptr,
        const std::optional<std::string>& cellSlug = std::nullopt);
    
    /**
     * Propose a molecule to the network
     * @param molecule The molecule to propose (takes ownership)
     * @param queryUri Optional specific URI to use
     * @return Future containing the proposal response
     * @note This method takes ownership of the molecule pointer
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    proposeMolecule(KnishIO::Molecule* molecule,
                    const std::optional<std::string>& queryUri = std::nullopt);

    // Token operations
    
    /**
     * Create a new token type
     * @param token The token slug
     * @param amount Initial amount to create
     * @param meta Optional metadata for the token
     * @return Future containing the creation response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseCreateToken>>
    createToken(const std::string& token, 
                double amount,
                const std::unordered_map<std::string, std::string>& meta = {});
    
    /**
     * Transfer tokens to another wallet
     * @param bundleHash Recipient's bundle hash
     * @param token Token slug to transfer
     * @param amount Amount to transfer
     * @return Future containing the transfer response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseTransferTokens>>
    transferToken(const std::string& bundleHash,
                  const std::string& token,
                  double amount);

    // Authentication
    
    /**
     * Request an authorization token
     * @param secret Optional secret (uses client secret if not provided)
     * @param cellSlug Optional cell slug
     * @param encrypt Whether to encrypt the communication
     * @return Future containing the authorization response
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseRequestAuthorization>>
    requestAuthToken(const std::optional<std::string>& secret = std::nullopt,
                     const std::optional<std::string>& cellSlug = std::nullopt,
                     bool encrypt = false);
    
    /**
     * Check if authenticated
     * @return true if authenticated, false otherwise
     */
    [[nodiscard]] bool isAuthenticated() const noexcept;

    // Utility methods
    
    /**
     * Generate a cryptographically secure secret
     * @param length Length of the secret in characters (default 2048)
     * @return Generated hexadecimal secret string
     */
    [[nodiscard]] static std::string generateSecret(size_t length = 2048);
    
    /**
     * Generate deterministic secret from seed (matches JavaScript SDK)
     * @param seed Input seed string for deterministic generation
     * @param length Length of the secret in hex characters (default 2048 — canonical, matches all SDKs)
     * @return Generated hexadecimal secret string
     */
    [[nodiscard]] static std::string generateSecret(const std::string& seed, size_t length = 2048);
    
    /**
     * Generate a batch ID for grouped operations
     * @param molecule The molecule to generate batch ID for
     * @return Generated batch ID
     */
    [[nodiscard]] static std::string generateBatchId(const KnishIO::Molecule& molecule);
    
    /**
     * Get SDK version information
     * @return Version string
     */
    [[nodiscard]] static std::string getVersion() noexcept;

private:
    // Private implementation (pImpl idiom for ABI stability)
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    // Internal helper methods
    [[nodiscard]] std::string getRandomUri() const;
    [[nodiscard]] std::string hashSecret(const std::string& secret) const;
    void log(const std::string& level, const std::string& message) const;
    void ensureAuthenticated() const;
    void validateConfig() const;
};

} // namespace knishio