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
#include "TokenUnit.h"

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
 * A KnishIOClient instance is not thread-safe; use one instance per thread or guard a
 * shared instance with a mutex. Wallet and Molecule signing/verification on separate
 * objects are thread-safe.
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
        int mlKemParameterSet = 1024;                     ///< ML-KEM parameter set (1024 default, 768 step-back)
    };

    /**
     * One destination of a multi-recipient stackable transfer (see transferTokens).
     * Provide EITHER units (stackable/NFT: amount = units.size()) OR amount (fungible), not both.
     * batchId makes the recipient a claimable shadow under that batch.
     */
    struct TransferRecipient {
        std::string bundleHash;
        double amount = 0.0;
        std::string batchId;
        std::vector<std::string> units;
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
        Builder& mlKemParameterSet(int parameterSet = 1024);
        
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
                const std::unordered_map<std::string, std::string>& meta = {},
                const std::vector<std::string>& units = {});
    
    /**
     * Transfer tokens to another wallet (batched/shadow transfer, mirroring JS transferToken)
     *
     * Builds a pure 3-V-atom value molecule: the source token wallet (resolved live via the
     * Balance query) is debited its full balance, the recipient bundle receives @p amount, and a
     * fresh remainder wallet holds the change. When @p batchId is set the recipient atom carries it
     * so the validator creates a claimable shadow wallet (later claimed via claimShadowWallet).
     *
     * @param bundleHash Recipient's bundle hash
     * @param token Token slug to transfer
     * @param amount Amount to transfer
     * @param batchId Optional batch id — required for a fresh recipient (no existing wallet for the
     *                token); set it so the recipient becomes a claimable shadow wallet
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    transferToken(const std::string& bundleHash,
                  const std::string& token,
                  double amount,
                  const std::string& batchId = "",
                  const std::vector<std::string>& units = {});

    /**
     * Multi-recipient transfer: fund N recipients from a single source in ONE molecule
     * (multi-recipient sibling of transferToken). Each recipient gets its own subset of stackable
     * units (or a fungible amount); a remainder returns the rest to the sender.
     * @param token Token slug to transfer
     * @param recipients Destinations (bundleHash + units OR amount + optional batchId)
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    transferTokens(const std::string& token,
                   const std::vector<TransferRecipient>& recipients);

    /**
     * Burn (destroy) tokens (mirroring JS burnToken)
     *
     * Builds a pure 3-V-atom value molecule: the source token wallet (resolved live via the Balance
     * query) is debited its full balance, @p amount is credited to the all-zeros burn bundle
     * (an unspendable destination — no batchId, so no claimable shadow), and a fresh remainder wallet
     * holds the change. Sum = 0. Reuses initValue with the burn bundle as the recipient.
     *
     * @param token Token slug to burn
     * @param amount Amount to burn
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    burnToken(const std::string& token, double amount, const std::vector<std::string>& units = {});

    /**
     * Deposit tokens into a buffer wallet (mirroring JS depositBufferToken).
     *
     * Builds a V-B-V molecule via Molecule::initDepositBuffer: the source token wallet (resolved live
     * via the Balance query) is debited its full balance, @p amount is credited to a FRESH buffer
     * wallet (B-isotope, walletBundle -> source bundle), and a fresh remainder wallet holds the change.
     * Conserves to 0 across V+B.
     *
     * @param token Token slug to deposit
     * @param amount Amount to move into the buffer
     * @param tradeRates Optional buffer trade-rate meta (serialized into the B atom only when non-empty)
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    depositBufferToken(const std::string& token, double amount,
                       const std::vector<std::pair<std::string, std::string>>& tradeRates = {});

    /**
     * Withdraw tokens from a buffer wallet back to the caller's own bundle (contract 9.6).
     *
     * Builds a B-V-B molecule via Molecule::initWithdrawBuffer: the source buffer wallet S is debited
     * its full balance (B-isotope), @p amount is credited to the caller's own bundle (an addressless
     * V atom, walletBundle -> own bundle, with a fresh batch id only when S has one), and a FRESH
     * remainder wallet (a new position, never S itself) receives S.balance - amount as a B atom.
     * Conserves to 0 across B+V. No ContinuID atom.
     *
     * @param token Token slug to withdraw
     * @param amount Amount to withdraw from the buffer
     * @param sourceWallet Optional buffer wallet to withdraw from (its position and balance must be
     *                     set); defaults to the bundle's buffer wallet from Balance(type: "buffer")
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    withdrawBufferToken(const std::string& token, double amount,
                        const KnishIO::Wallet* sourceWallet = nullptr);

    /**
     * Mint more supply of an existing token (contract 9.1).
     *
     * Builds a C (metaType "token", meta action = "add") + ContinuID molecule signed from the bundle's
     * ContinuID pointer, crediting the identity's existing wallet for the token (from Balance) or a new
     * one. Only the token's creator may replenish, and only a token whose supply is "infinite" or
     * "replenishable"; the validator enforces both.
     *
     * @param token Token slug to replenish
     * @param amount Supply to add (fungible); must be > 0. With @p units it must be 0 or units.size()
     * @param units New stackable / non-fungible unit ids; the minted value is then their count
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    replenishToken(const std::string& token, double amount,
                   const std::vector<std::string>& units = {});

    /**
     * Fuse stackable units into one new unit (contract 9.2).
     *
     * Builds V(source -B) + V(burn +(M-1)) + F(recipient +1) + V(remainder +(B-M)) from the bundle's
     * wallet for @p tokenSlug (from Balance). The new unit carries metas.fusedTokenUnits = the fused
     * units. No ContinuID atom.
     *
     * @param bundleHash Recipient bundle of the new unit (the caller's own bundle or another)
     * @param tokenSlug Stackable token slug
     * @param newTokenUnitId Id (and name) of the new unit; must not exist in the source wallet
     * @param fusedTokenUnitIds Ids of the units to fuse (at least two), in caller order
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    fuseToken(const std::string& bundleHash, const std::string& tokenSlug,
              const std::string& newTokenUnitId, const std::vector<std::string>& fusedTokenUnitIds);

    /**
     * Create a new wallet on the ledger (C-isotope metaType "wallet" + ContinuID)
     * @param token Token slug for the new wallet
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    createWallet(const std::string& token);

    /**
     * Attach metadata to an arbitrary (metaType, metaId) on the ledger (M-isotope + ContinuID),
     * signed by the USER wallet at the bundle's live ContinuID position.
     * @param metaType Meta type, e.g. "EdgeBench"
     * @param metaId   Meta instance id
     * @param meta     Key/value pairs, in order
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    createMeta(const std::string& metaType, const std::string& metaId,
               const std::vector<std::pair<std::string, std::string>>& meta);

    /**
     * Claim a shadow wallet (an address-less wallet created by a batched transfer)
     * @param token Token slug to claim
     * @param batchId Batch id identifying the shadow wallet
     * @return Future containing the ProposeMolecule response (use isAccepted())
     */
    [[nodiscard]] std::future<std::unique_ptr<response::ResponseProposeMolecule>>
    claimShadowWallet(const std::string& token, const std::string& batchId);

    // Authentication
    
    /**
     * Request an authorization token
     *
     * A returning user (the bundle's ContinuId(token: USER) names a USER wallet this secret
     * derives) signs from that ContinuID pointer, so the validator issues a proven token; a first
     * login, or one with no usable pointer, signs from a fresh AUTH wallet. A rejected
     * pointer-signed login falls back once to the AUTH wallet (at most two auth molecules).
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
     * PQ-transport (Phase E): toggle the ML-KEM CipherHash encrypted transport on the active
     * session (the cipher context — wallet + validator pubkey — was plumbed at auth).
     * @param encrypt True to encrypt subsequent requests.
     */
    void switchEncryption(bool encrypt);
    
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

    // Live-wiring helpers (slice 4): sign + submit a molecule via ProposeMolecule, and resolve a
    // bundle's live on-ledger ContinuID position so a non-U molecule signs at the chain head.
    // checkBeforeSend runs Molecule::check on the signed molecule and sends nothing when it throws
    // (contract 9.7: every molecule a client operation builds); proposeMolecule, the raw path for a
    // caller-built molecule, passes false.
    [[nodiscard]] std::unique_ptr<response::ResponseProposeMolecule> submitMolecule(KnishIO::Molecule& mol, bool checkBeforeSend = true);
    [[nodiscard]] std::string resolveContinuIdPosition(const std::string& bundle);

    // Live-wiring helper (slice 5b): a bundle's on-ledger token wallet (from the Balance query) —
    // the spendable source for a value transfer. The position/balance MUST come from the validator
    // (createToken registers the token wallet at a random position; it isn't recoverable otherwise).
    struct TokenWalletInfo {
        std::string position;
        std::string address;
        std::string balance;   // the on-ledger amount (validator returns it as a string)
        std::string batchId;   // the wallet's batch id, if it has one
        bool found = false;
        std::vector<KnishIO::TokenUnit> tokenUnits;  // stackable (NFT) units, if the wallet has any
    };
    // buffer = true reads Balance(type: "buffer"), the bundle's buffer wallet; false its regular one.
    [[nodiscard]] TokenWalletInfo resolveTokenWallet(const std::string& bundle, const std::string& token, bool buffer = false);

    // Unit tests reach submitMolecule through this to prove the pre-submit check (tests/phaseb_molecules.cpp).
    friend class KnishIOClientTestAccess;
};

} // namespace knishio