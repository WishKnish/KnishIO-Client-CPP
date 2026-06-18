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
            if (config.insecureTls) {
                httpClient->setVerifySSL(false);
            }
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

KnishIOClient::Builder& KnishIOClient::Builder::insecureTls(bool enable) {
    config_.insecureTls = enable;
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
        const std::string b = bundle.value_or(getBundle());
        log("INFO", "Querying balance for token: " + token);

        // Resolve the on-ledger token wallet, then wrap it into the Balance shape that
        // ResponseBalance::parseData expects (data["Balance"].{position,address,amount,...}).
        TokenWalletInfo tw = resolveTokenWallet(b, token);

        auto result = std::make_unique<response::ResponseBalance>();
        if (tw.found) {
            nlohmann::json balanceData;
            balanceData["Balance"] = {
                {"position", tw.position},
                {"address", tw.address},
                {"amount", tw.balance},
                {"tokenSlug", token},
                {"bundleHash", b}
            };
            result->setData(balanceData);
            result->parseData();
        }
        return result;
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

// Sign + submit a molecule via ProposeMolecule (sync; reused by proposeMolecule + the token ops).
// Serializes + strips the validation-context wallets the validator's MoleculeInput rejects.
std::unique_ptr<response::ResponseProposeMolecule>
KnishIOClient::submitMolecule(KnishIO::Molecule& mol) {
    if (!hasSecret()) {
        throw KnishIOException("No secret available for signing molecule");
    }

    mol.sign(pImpl_->secret.value());
    if (!Molecule::verify(mol)) {
        throw KnishIOException("Molecule validation failed");
    }

    nlohmann::json moleculeJson = nlohmann::json::parse(mol.toJson());
    moleculeJson.erase("sourceWallet");
    moleculeJson.erase("remainderWallet");

    static const std::string PROPOSE_MOLECULE =
        "mutation ProposeMolecule($molecule: MoleculeInput!) {"
        " ProposeMolecule(molecule: $molecule) {"
        " molecularHash status reason payload createdAt } }";
    nlohmann::json variables;
    variables["molecule"] = moleculeJson;

    log("INFO", "Proposing molecule with hash: " + mol.molecularHash);

    auto httpResp = pImpl_->httpClient->mutate(PROPOSE_MOLECULE, variables).get();

    auto result = std::make_unique<response::ResponseProposeMolecule>();
    if (!httpResp.isSuccess()) {
        result->setError("Molecule proposal failed (HTTP " + std::to_string(httpResp.statusCode) + ")");
        return result;
    }
    nlohmann::json body = nlohmann::json::parse(httpResp.body);
    result->setData(body.contains("data") && !body["data"].is_null() ? body["data"] : body);
    return result;
}

// Resolve a bundle's live on-ledger ContinuID position (the chain head a non-U molecule must sign
// at). Queries the PUBLIC ContinuId(bundle, "USER"); returns the 64-char position, or "" for a
// genesis bundle (no ContinuID yet -> the caller falls back to a fresh random position).
std::string KnishIOClient::resolveContinuIdPosition(const std::string& bundle) {
    static const std::string CONTINUID_QUERY =
        "query ContinuId($bundle: String, $token: String) {"
        " ContinuId(bundle: $bundle, token: $token) {"
        " position address tokenSlug bundleHash pubkey characters } }";
    nlohmann::json variables;
    variables["bundle"] = bundle;
    variables["token"] = "USER";
    try {
        auto httpResp = pImpl_->httpClient->query(CONTINUID_QUERY, variables).get();
        if (httpResp.isSuccess()) {
            nlohmann::json body = nlohmann::json::parse(httpResp.body);
            if (body.contains("data") && body["data"].contains("ContinuId")
                && body["data"]["ContinuId"].is_object()) {
                const auto& cid = body["data"]["ContinuId"];
                if (cid.contains("position") && cid["position"].is_string()) {
                    std::string pos = cid["position"].get<std::string>();
                    if (pos.size() == 64) {
                        return pos;
                    }
                }
            }
        }
    } catch (const std::exception&) {
        // fall through to genesis (empty position)
    }
    return {};
}

// Resolve a bundle's live on-ledger token wallet via the PUBLIC Balance query — the spendable
// source for a value transfer. The validator's Balance(bundleHash, token) returns the highest-
// balance NON-shadow wallet (address + position present) with its amount. found=false when the
// bundle holds no spendable wallet for the token. Mirrors resolveContinuIdPosition's inline style.
// The position/balance MUST come from the validator: createToken registered the token wallet at a
// random position (not recoverable client-side), and the V-isotope signer must sign at that
// registered position.
KnishIOClient::TokenWalletInfo
KnishIOClient::resolveTokenWallet(const std::string& bundle, const std::string& token) {
    static const std::string BALANCE_QUERY =
        "query($bundleHash: String, $token: String) {"
        " Balance(bundleHash: $bundleHash, token: $token) {"
        " position address tokenSlug amount pubkey batchId bundleHash } }";
    nlohmann::json variables;
    variables["bundleHash"] = bundle;
    variables["token"] = token;

    TokenWalletInfo info;
    try {
        auto httpResp = pImpl_->httpClient->query(BALANCE_QUERY, variables).get();
        if (httpResp.isSuccess()) {
            nlohmann::json body = nlohmann::json::parse(httpResp.body);
            if (body.contains("data") && body["data"].contains("Balance")
                && body["data"]["Balance"].is_object()) {
                const auto& bal = body["data"]["Balance"];
                if (bal.contains("position") && bal["position"].is_string()) {
                    info.position = bal["position"].get<std::string>();
                }
                if (bal.contains("address") && bal["address"].is_string()) {
                    info.address = bal["address"].get<std::string>();
                }
                if (bal.contains("amount") && bal["amount"].is_string()) {
                    info.balance = bal["amount"].get<std::string>();
                }
                // A spendable (non-shadow) source must have a real position + address.
                info.found = !info.position.empty() && !info.address.empty();
            }
        }
    } catch (const std::exception&) {
        // fall through: found stays false
    }
    return info;
}

std::future<std::unique_ptr<response::ResponseProposeMolecule>>
KnishIOClient::proposeMolecule(Molecule* molecule,
                              const std::optional<std::string>& queryUri) {
    std::unique_ptr<Molecule> mol(molecule);
    (void)queryUri;
    return std::async(std::launch::async, [this, mol = std::move(mol)]() -> std::unique_ptr<response::ResponseProposeMolecule> {
        return submitMolecule(*mol);
    });
}

// Token operations
std::future<std::unique_ptr<response::ResponseCreateToken>>
KnishIOClient::createToken(const std::string& token,
                          double amount,
                          const std::unordered_map<std::string, std::string>& meta) {
    return std::async(std::launch::async, [this, token, amount, meta]() -> std::unique_ptr<response::ResponseCreateToken> {
        ensureAuthenticated();
        const std::string sec = pImpl_->secret.value();

        // The SOURCE signs at the bundle's LIVE ContinuID position (else the validator rejects
        // "ContinuID chain validation failed"). The recipient is the new token's wallet; the
        // remainder is a fresh chain head (the relay race).
        const std::string bundle = getBundle();
        const std::string livePos = resolveContinuIdPosition(bundle);
        Wallet source(sec, "USER", livePos);   // livePos == "" -> fresh random (genesis)
        Wallet recipient(sec, token);          // new-token wallet, fresh random position
        Wallet remainder(sec, "USER");         // fresh random remainder

        std::vector<std::pair<std::string, std::string>> tokenMeta;
        tokenMeta.reserve(meta.size());
        for (const auto& [k, v] : meta) {
            tokenMeta.push_back({k, v});
        }

        Molecule mol(pImpl_->config.cellSlug.value_or(std::string{}));
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initTokenCreation(source, recipient, std::to_string(static_cast<long long>(amount)), tokenMeta);

        log("INFO", "Creating token: " + token + " amount: " + std::to_string(amount));

        auto proposeResp = submitMolecule(mol);

        auto result = std::make_unique<response::ResponseCreateToken>();
        result->setData(proposeResp->getData());
        return result;
    });
}

// Wallet operations
std::future<std::unique_ptr<response::ResponseProposeMolecule>>
KnishIOClient::createWallet(const std::string& token) {
    return std::async(std::launch::async, [this, token]() -> std::unique_ptr<response::ResponseProposeMolecule> {
        ensureAuthenticated();
        const std::string sec = pImpl_->secret.value();

        const std::string livePos = resolveContinuIdPosition(getBundle());
        Wallet source(sec, "USER", livePos);   // sign at the live ContinuID position
        Wallet newWallet(sec, token);          // the wallet being defined (fresh position)
        Wallet remainder(sec, "USER");         // fresh remainder (relay race)

        Molecule mol(pImpl_->config.cellSlug.value_or(std::string{}));
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initWalletCreation(source, newWallet);

        log("INFO", "Creating wallet for token: " + token);
        return submitMolecule(mol);
    });
}

std::future<std::unique_ptr<response::ResponseProposeMolecule>>
KnishIOClient::claimShadowWallet(const std::string& token, const std::string& batchId) {
    return std::async(std::launch::async, [this, token, batchId]() -> std::unique_ptr<response::ResponseProposeMolecule> {
        ensureAuthenticated();
        const std::string sec = pImpl_->secret.value();

        const std::string livePos = resolveContinuIdPosition(getBundle());
        Wallet source(sec, "USER", livePos);   // sign at the live ContinuID position
        Wallet claimWallet(sec, token);        // the shadow wallet being claimed
        claimWallet.batchId = batchId;         // -> walletBatchId meta (validator matches by it)
        Wallet remainder(sec, "USER");         // fresh remainder

        Molecule mol(pImpl_->config.cellSlug.value_or(std::string{}));
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initShadowWalletClaim(source, claimWallet);

        log("INFO", "Claiming shadow wallet token: " + token + " batch: " + batchId);
        return submitMolecule(mol);
    });
}

std::future<std::unique_ptr<response::ResponseProposeMolecule>>
KnishIOClient::transferToken(const std::string& bundleHash,
                            const std::string& token,
                            double amount,
                            const std::string& batchId) {
    return std::async(std::launch::async, [this, bundleHash, token, amount, batchId]() -> std::unique_ptr<response::ResponseProposeMolecule> {
        ensureAuthenticated();
        const std::string sec = pImpl_->secret.value();
        const std::string senderBundle = getBundle();

        // 1. SOURCE: the bundle's on-ledger token wallet. Its position + balance come from the
        //    validator's Balance query (createToken registered it at a random position; the
        //    V-isotope signer must sign at that registered position).
        TokenWalletInfo src = resolveTokenWallet(senderBundle, token);
        if (!src.found) {
            throw KnishIOException("No spendable wallet for token " + token);
        }
        const long long amountLL = static_cast<long long>(amount);
        long long srcBalance = 0;
        try { srcBalance = std::stoll(src.balance); } catch (const std::exception&) { srcBalance = 0; }
        if (srcBalance < amountLL) {
            throw KnishIOException("Insufficient balance for token " + token);
        }

        Wallet source(sec, token, src.position);  // re-derives the registered address from secret+token+position
        source.balance = src.balance;             // initValue debits the full balance (UTXO pattern)

        // 2. RECIPIENT: a shadow wallet for the recipient bundle (we have no secret for it -> no
        //    position/address; identified by bundle + token + batchId). The validator's recipient
        //    path keys off metaId(=bundle) + batchId; the empty address/position are ignored on the
        //    shadow branch, and a fresh recipient REQUIRES the batchId.
        Wallet recipient(sec, token);
        recipient.bundle = bundleHash;
        recipient.address = "";
        recipient.position = "";
        recipient.batchId = batchId;   // -> recipient V-atom batchId; validator creates a claimable shadow

        // 3. REMAINDER: a fresh same-token wallet (new position) holding (balance - amount); the
        //    validator registers it, advancing the sender's chain.
        Wallet remainder(sec, token);

        // 4. Pure 3-V value molecule (NO ContinuID I-atom — the sender is non-genesis, having funded
        //    the token). initValue: V0 source -balance, V1 recipient +amount, V2 remainder +change.
        Molecule mol(pImpl_->config.cellSlug.value_or(std::string{}));
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initValue(source, recipient, remainder, std::to_string(amountLL));

        log("INFO", "Transferring " + std::to_string(amountLL) + " " + token + " to " + bundleHash);
        return submitMolecule(mol);
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
        const std::string sec = pImpl_->secret.value();

        // Build the U-isotope authorization molecule. The AUTH source + USER remainder both use
        // random positions (Wallet default) so re-auth is OTS-safe. U-isotope ProposeMolecule is
        // PUBLIC (no prior token); the validator extracts the pubkey from the U-atom + issues a
        // bundle-scoped JWT.
        Wallet source(sec, "AUTH");
        Wallet remainder(sec, "USER");
        const std::string cell = cellSlug.value_or(pImpl_->config.cellSlug.value_or(std::string{}));
        Molecule mol(cell);
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initAuthorization(source, encrypt);
        mol.sign(sec);

        // Serialize + strip the validation-context wallets (the validator's MoleculeInput rejects
        // unknown sourceWallet/remainderWallet fields — toJson emits them when set).
        nlohmann::json moleculeJson = nlohmann::json::parse(mol.toJson());
        moleculeJson.erase("sourceWallet");
        moleculeJson.erase("remainderWallet");

        static const std::string PROPOSE_MOLECULE =
            "mutation ProposeMolecule($molecule: MoleculeInput!) {"
            " ProposeMolecule(molecule: $molecule) {"
            " molecularHash status reason payload createdAt } }";
        nlohmann::json variables;
        variables["molecule"] = moleculeJson;

        log("INFO", "Requesting authorization token (molecular hash: " + mol.molecularHash + ")");

        auto httpResp = pImpl_->httpClient->mutate(PROPOSE_MOLECULE, variables).get();

        auto result = std::make_unique<response::ResponseRequestAuthorization>();
        if (!httpResp.isSuccess()) {
            result->setError("Authorization request failed (HTTP " + std::to_string(httpResp.statusCode) + ")");
            return result;
        }

        nlohmann::json body = nlohmann::json::parse(httpResp.body);
        result->setData(body.contains("data") && !body["data"].is_null() ? body["data"] : body);

        // Extract the JWT from data.ProposeMolecule.payload (a stringified JSON) -> token, and set
        // it on the client + the http transport (so subsequent ops carry the X-Auth-Token header).
        if (body.contains("data") && body["data"].contains("ProposeMolecule")) {
            const auto& pm = body["data"]["ProposeMolecule"];
            if (pm.contains("payload") && pm["payload"].is_string()) {
                try {
                    nlohmann::json payload = nlohmann::json::parse(pm["payload"].get<std::string>());
                    if (payload.contains("token") && payload["token"].is_string()) {
                        const std::string jwt = payload["token"].get<std::string>();
                        pImpl_->authToken = jwt;
                        pImpl_->httpClient->setAuthToken(jwt);
                    }
                } catch (const std::exception&) {
                    // payload not parseable (e.g. a rejected molecule) -> leave authToken unset
                }
            }
        }
        return result;
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