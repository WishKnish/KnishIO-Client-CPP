#include "KnishIOClient.h"
#include "Wallet.h"
#include "Molecule.h"
#include "utility.h"
#include "exception/KnishIOException.h"
#include "http/GraphQLClient.h"
#include "response/Response.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <sodium.h>
#include <algorithm>
#include <thread>

namespace knishio {

// Import KnishIO namespace types
using KnishIO::Wallet;
using KnishIO::Molecule;
using KnishIO::Atom;

// Version information
constexpr const char* SDK_VERSION = "0.8.1";

// Forward declare implementation class
class KnishIOClient::Impl {
public:
    Config config;
    std::optional<std::string> secret;
    std::optional<std::string> bundle;
    std::unique_ptr<Wallet> authWallet;
    std::unique_ptr<http::GraphQLClient> httpClient;
    std::optional<std::string> authToken;
    mutable std::mt19937 rng{std::random_device{}()};

    explicit Impl(const Config& cfg) 
        : config(cfg) {
        // Initialize HTTP client with first URI
        if (!config.uris.empty()) {
            httpClient = std::make_unique<http::GraphQLClient>(
                config.uris[0], 
                config.timeout.count(), 
                config.maxRetries
            );
        }
    }

    ~Impl() {
        // Securely clear sensitive data
        if (secret.has_value()) {
            sodium_memzero(const_cast<char*>(secret->data()), secret->size());
        }
        if (authToken.has_value()) {
            sodium_memzero(const_cast<char*>(authToken->data()), authToken->size());
        }
    }
};

// Builder implementation
KnishIOClient::Builder& KnishIOClient::Builder::uris(const std::vector<std::string>& uris) {
    config_.uris = uris;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::cellSlug(const std::string& cellSlug) {
    config_.cellSlug = cellSlug;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::serverSdkVersion(int version) {
    config_.serverSdkVersion = version;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::enableLogging(bool enable) {
    config_.logging = enable;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::enableEncryption(bool enable) {
    config_.encrypt = enable;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::timeout(std::chrono::milliseconds timeout) {
    config_.timeout = timeout;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::maxRetries(int retries) {
    config_.maxRetries = retries;
    return *this;
}

KnishIOClient::Builder& KnishIOClient::Builder::retryDelay(std::chrono::milliseconds delay) {
    config_.retryDelay = delay;
    return *this;
}

std::unique_ptr<KnishIOClient> KnishIOClient::Builder::build() const {
    if (config_.uris.empty()) {
        throw KnishIOException("At least one URI must be provided");
    }
    return std::make_unique<KnishIOClient>(config_);
}

// Main class implementation
KnishIOClient::KnishIOClient(const Config& config) 
    : pImpl_(std::make_unique<Impl>(config)) {
    // Initialize libsodium if not already initialized
    if (sodium_init() < 0) {
        throw KnishIOException("Failed to initialize libsodium");
    }
    
    validateConfig();
    log("INFO", "KnishIOClient initialized with " + 
        std::to_string(config.uris.size()) + " node URI(s)");
}

KnishIOClient::~KnishIOClient() = default;

// Move constructor
KnishIOClient::KnishIOClient(KnishIOClient&&) noexcept = default;

// Move assignment operator
KnishIOClient& KnishIOClient::operator=(KnishIOClient&&) noexcept = default;

// Configuration management
void KnishIOClient::setCellSlug(const std::string& cellSlug) {
    pImpl_->config.cellSlug = cellSlug;
    log("DEBUG", "Cell slug set to: " + cellSlug);
}

std::optional<std::string> KnishIOClient::getCellSlug() const noexcept {
    return pImpl_->config.cellSlug;
}

void KnishIOClient::setSecret(const std::string& secret) {
    if (secret.empty()) {
        throw KnishIOException("Secret cannot be empty");
    }
    
    // Validate hexadecimal format
    if (!std::all_of(secret.begin(), secret.end(), 
        [](char c) { return std::isxdigit(c); })) {
        throw KnishIOException("Secret must be a hexadecimal string");
    }
    
    pImpl_->secret = secret;
    
    // Generate wallet from secret
    pImpl_->authWallet = std::make_unique<Wallet>(secret);
    pImpl_->bundle = Wallet::generateBundleHash(secret);
    
    log("DEBUG", "Secret set and wallet initialized");
}

bool KnishIOClient::hasSecret() const noexcept {
    return pImpl_->secret.has_value();
}

std::string KnishIOClient::getBundle() const {
    if (!pImpl_->bundle.has_value()) {
        throw KnishIOException("No bundle available - secret must be set first");
    }
    return pImpl_->bundle.value();
}

// Wallet operations
std::future<std::unique_ptr<response::ResponseBalance>> 
KnishIOClient::queryBalance(const std::string& token, 
                           const std::optional<std::string>& bundle) {
    return std::async(std::launch::async, [this, token, bundle]() -> std::unique_ptr<response::ResponseBalance> {
        ensureAuthenticated();
        
        // TODO: Implement QueryBalance when query classes are ready
        log("INFO", "Querying balance for token: " + token);
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

std::future<std::unique_ptr<response::ResponseWalletList>> 
KnishIOClient::queryWallets(const std::optional<std::string>& bundle,
                           const std::optional<std::string>& token) {
    return std::async(std::launch::async, [this, bundle, token]() -> std::unique_ptr<response::ResponseWalletList> {
        ensureAuthenticated();
        
        // TODO: Implement QueryWalletList when query classes are ready
        log("INFO", "Querying wallet list");
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

std::future<std::unique_ptr<response::ResponseContinuId>> 
KnishIOClient::queryContinuId(const std::string& bundle) {
    return std::async(std::launch::async, [this, bundle]() -> std::unique_ptr<response::ResponseContinuId> {
        // ContinuId queries don't require authentication
        
        // TODO: Implement QueryContinuId when query classes are ready
        log("INFO", "Querying ContinuID for bundle: " + bundle);
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

// Molecule operations
Molecule* KnishIOClient::createMolecule(
    const std::optional<std::string>& secret,
    Wallet* sourceWallet,
    const std::optional<std::string>& cellSlug) {
    
    // Use provided secret or client secret
    std::string moleculeSecret;
    if (secret.has_value()) {
        moleculeSecret = secret.value();
    } else if (hasSecret()) {
        moleculeSecret = pImpl_->secret.value();
    } else {
        throw KnishIOException("No secret available for molecule creation");
    }
    
    // Use provided cell slug or client cell slug
    std::optional<std::string> moleculeCellSlug = cellSlug;
    if (!moleculeCellSlug.has_value()) {
        moleculeCellSlug = pImpl_->config.cellSlug;
    }
    
    // Create molecule and return raw pointer
    // Caller is responsible for managing the memory
    Molecule* molecule = new Molecule(moleculeCellSlug.value_or(""));
    
    // Clean up source wallet if provided (we took ownership)
    if (sourceWallet) {
        delete sourceWallet;
    }
    
    log("DEBUG", "Molecule created");
    return molecule;
}

std::future<std::unique_ptr<response::ResponseProposeMolecule>>
KnishIOClient::proposeMolecule(Molecule* molecule,
                              const std::optional<std::string>& queryUri) {
    // Take ownership of the molecule using unique_ptr
    std::unique_ptr<Molecule> mol(molecule);
    
    return std::async(std::launch::async, [this, mol = std::move(mol), queryUri]() -> std::unique_ptr<response::ResponseProposeMolecule> {
        // Sign molecule with secret before proposing
        if (!hasSecret()) {
            throw KnishIOException("No secret available for signing molecule");
        }
        
        mol->sign(pImpl_->secret.value());
        
        // Verify molecule is valid
        if (!Molecule::verify(*mol)) {
            throw KnishIOException("Molecule validation failed");
        }
        
        // TODO: Implement MutationProposeMolecule when mutation classes are ready
        log("INFO", "Proposing molecule with hash: " + mol->molecularHash);
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

// Token operations
std::future<std::unique_ptr<response::ResponseCreateToken>>
KnishIOClient::createToken(const std::string& token, 
                          double amount,
                          const std::unordered_map<std::string, std::string>& meta) {
    return std::async(std::launch::async, [this, token, amount, meta]() -> std::unique_ptr<response::ResponseCreateToken> {
        ensureAuthenticated();
        
        // TODO: Implement token creation via molecule
        log("INFO", "Creating token: " + token + " with amount: " + std::to_string(amount));
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

std::future<std::unique_ptr<response::ResponseTransferTokens>>
KnishIOClient::transferToken(const std::string& bundleHash,
                            const std::string& token,
                            double amount) {
    return std::async(std::launch::async, [this, bundleHash, token, amount]() -> std::unique_ptr<response::ResponseTransferTokens> {
        ensureAuthenticated();
        
        // TODO: Implement token transfer via molecule
        log("INFO", "Transferring " + std::to_string(amount) + " " + token + 
            " to " + bundleHash);
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

// Authentication
std::future<std::unique_ptr<response::ResponseRequestAuthorization>>
KnishIOClient::requestAuthToken(const std::optional<std::string>& secret,
                               const std::optional<std::string>& cellSlug,
                               bool encrypt) {
    return std::async(std::launch::async, [this, secret, cellSlug, encrypt]() -> std::unique_ptr<response::ResponseRequestAuthorization> {
        // Use provided secret or client secret
        if (secret.has_value()) {
            setSecret(secret.value());
        } else if (!hasSecret()) {
            throw KnishIOException("No secret available for authentication");
        }
        
        // TODO: Implement authorization request
        log("INFO", "Requesting authorization token");
        
        // Placeholder implementation - return nullptr for now
        return nullptr;
    });
}

bool KnishIOClient::isAuthenticated() const noexcept {
    return pImpl_->authToken.has_value() && !pImpl_->authToken->empty();
}

// Utility methods
std::string KnishIOClient::generateSecret(size_t length) {
    if (length == 0 || length % 2 != 0) {
        throw KnishIOException("Secret length must be positive and even");
    }
    
    // Generate random bytes
    size_t byteLength = length / 2;
    std::vector<unsigned char> randomBytes(byteLength);
    randombytes_buf(randomBytes.data(), byteLength);
    
    // Convert to hexadecimal string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : randomBytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::string KnishIOClient::generateSecret(const std::string& seed, size_t length) {
    if (seed.empty()) {
        throw KnishIOException("Seed cannot be empty for deterministic generation");
    }
    
    if (length == 0 || length % 2 != 0) {
        throw KnishIOException("Secret length must be positive and even");
    }
    
    // Generate deterministic secret using SHAKE256 with seed (matches JS/Python exactly).
    // `length` hex chars = length*4 bits, uniformly (e.g. 128 -> 512 bits -> 64 bytes -> 128 hex),
    // matching JS/Python generateSecret(seed, 128) used to derive the 64-byte ML-KEM seed.
    size_t bits = length * 4;
    return shake256Hex(seed, bits);
}

std::string KnishIOClient::generateBatchId(const Molecule& molecule) {
    // Generate batch ID based on molecule properties
    std::string source = molecule.molecularHash + 
                        std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    
    // Hash the source to create batch ID
    std::vector<unsigned char> hash(32);
    crypto_generichash(hash.data(), hash.size(),
                      reinterpret_cast<const unsigned char*>(source.data()),
                      source.size(), nullptr, 0);
    
    // Convert to hex
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::string KnishIOClient::getVersion() noexcept {
    return SDK_VERSION;
}

// Internal helper methods
std::string KnishIOClient::getRandomUri() const {
    if (pImpl_->config.uris.empty()) {
        throw KnishIOException("No URIs available");
    }
    
    if (pImpl_->config.uris.size() == 1) {
        return pImpl_->config.uris[0];
    }
    
    // Select random URI for load balancing
    std::uniform_int_distribution<size_t> dist(0, pImpl_->config.uris.size() - 1);
    return pImpl_->config.uris[dist(pImpl_->rng)];
}

std::string KnishIOClient::hashSecret(const std::string& secret) const {
    std::vector<unsigned char> hash(32);
    crypto_generichash(hash.data(), hash.size(),
                      reinterpret_cast<const unsigned char*>(secret.data()),
                      secret.size(), nullptr, 0);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    
    return oss.str();
}

void KnishIOClient::log(const std::string& level, const std::string& message) const {
    if (!pImpl_->config.logging) {
        return;
    }
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") 
              << "] [" << level << "] " << message << std::endl;
}

void KnishIOClient::ensureAuthenticated() const {
    if (!isAuthenticated()) {
        throw KnishIOException("Authentication required for this operation");
    }
}

void KnishIOClient::validateConfig() const {
    if (pImpl_->config.uris.empty()) {
        throw KnishIOException("At least one URI must be configured");
    }
    
    // Validate URIs format
    for (const auto& uri : pImpl_->config.uris) {
        if (uri.empty() || (uri.find("http://") != 0 && uri.find("https://") != 0)) {
            throw KnishIOException("Invalid URI format: " + uri);
        }
    }
    
    if (pImpl_->config.timeout.count() <= 0) {
        throw KnishIOException("Timeout must be positive");
    }
    
    if (pImpl_->config.maxRetries < 0) {
        throw KnishIOException("Max retries cannot be negative");
    }
}

} // namespace knishio