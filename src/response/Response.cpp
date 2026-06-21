#include "response/Response.h"

namespace knishio {
namespace response {

namespace {
// The auth molecule's JWT + pubkey live in data.ProposeMolecule.payload, a STRINGIFIED JSON
// (the validator funnels every op through ProposeMolecule). Returns the parsed payload object,
// or an empty object when absent/null/unparseable.
nlohmann::json parseProposePayload(const nlohmann::json& data) {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].is_object()
        && data["ProposeMolecule"].contains("payload")
        && data["ProposeMolecule"]["payload"].is_string()) {
        try {
            return nlohmann::json::parse(data["ProposeMolecule"]["payload"].get<std::string>());
        } catch (const std::exception&) {
            // malformed payload -> empty object
        }
    }
    return nlohmann::json::object();
}
} // anonymous namespace

// ResponseBalance implementation
std::optional<ResponseBalance::Balance> ResponseBalance::getBalance() const {
    return balance;
}

void ResponseBalance::parseData() {
    if (data.contains("Balance") && !data["Balance"].is_null()) {
        Balance b;
        auto balanceData = data["Balance"];
        
        if (balanceData.contains("address")) b.address = balanceData["address"];
        if (balanceData.contains("bundleHash")) b.bundleHash = balanceData["bundleHash"];
        if (balanceData.contains("tokenSlug")) b.tokenSlug = balanceData["tokenSlug"];
        if (balanceData.contains("amount")) b.amount = balanceData["amount"];
        if (balanceData.contains("position")) b.position = balanceData["position"];
        if (balanceData.contains("batchId")) b.batchId = balanceData["batchId"];
        
        // The validator returns `characters` as a single String (e.g. "BASE64"); tolerate an
        // array shape too for older producers.
        if (balanceData.contains("characters")) {
            const auto& chars = balanceData["characters"];
            if (chars.is_string()) {
                b.characters.push_back(chars.get<std::string>());
            } else if (chars.is_array()) {
                for (const auto& ch : chars) {
                    if (ch.is_string()) b.characters.push_back(ch.get<std::string>());
                }
            }
        }

        // Stackable (NFT) units the wallet holds. Canonical shape: tokenUnits[{id,name,metas}].
        // Mirrors KnishIOClient.cpp::parseWalletTokenUnits so a C++ consumer can read units back
        // (the validator serves Wallet.tokenUnits as of the stackable Phase-1 work).
        if (balanceData.contains("tokenUnits") && balanceData["tokenUnits"].is_array()) {
            for (const auto& u : balanceData["tokenUnits"]) {
                KnishIO::TokenUnit tu;
                if (u.contains("id") && u["id"].is_string()) tu.id = u["id"].get<std::string>();
                if (u.contains("name") && u["name"].is_string()) tu.name = u["name"].get<std::string>();
                if (u.contains("metas") && u["metas"].is_object()) {
                    for (auto it = u["metas"].begin(); it != u["metas"].end(); ++it) {
                        if (it.value().is_string()) tu.metas[it.key()] = it.value().get<std::string>();
                    }
                }
                b.tokenUnits.push_back(std::move(tu));
            }
        }

        balance = b;
    }
}

// ResponseWalletList implementation
void ResponseWalletList::parseData() {
    wallets.clear();

    // The validator query is `wallets(bundleHash) -> [Wallet]`; tolerate the older "WalletList" key.
    const char* key = data.contains("wallets") ? "wallets"
                    : (data.contains("WalletList") ? "WalletList" : nullptr);
    if (key && data[key].is_array()) {
        for (const auto& walletData : data[key]) {
            Wallet w;

            if (walletData.contains("address") && walletData["address"].is_string())
                w.address = walletData["address"].get<std::string>();
            if (walletData.contains("bundleHash") && walletData["bundleHash"].is_string())
                w.bundleHash = walletData["bundleHash"].get<std::string>();
            // Validator returns `tokenSlug`; tolerate `token`.
            if (walletData.contains("tokenSlug") && walletData["tokenSlug"].is_string())
                w.token = walletData["tokenSlug"].get<std::string>();
            else if (walletData.contains("token") && walletData["token"].is_string())
                w.token = walletData["token"].get<std::string>();
            if (walletData.contains("position") && walletData["position"].is_string())
                w.position = walletData["position"].get<std::string>();
            if (walletData.contains("pubkey") && walletData["pubkey"].is_string())
                w.pubkey = walletData["pubkey"].get<std::string>();
            if (walletData.contains("balance") && walletData["balance"].is_string())
                w.balance = walletData["balance"].get<std::string>();
            else if (walletData.contains("amount") && walletData["amount"].is_string())
                w.balance = walletData["amount"].get<std::string>();

            wallets.push_back(w);
        }
    }
}

// ResponseContinuId implementation
void ResponseContinuId::parseData() {
    if (data.contains("ContinuId") && data["ContinuId"].is_object()) {
        ContinuID c;
        const auto& continuData = data["ContinuId"];

        // Validator ContinuId returns: position, address, tokenSlug, bundleHash, pubkey, characters.
        if (continuData.contains("position") && continuData["position"].is_string())
            c.position = continuData["position"].get<std::string>();
        if (continuData.contains("address") && continuData["address"].is_string())
            c.walletAddress = continuData["address"].get<std::string>();
        if (continuData.contains("bundleHash") && continuData["bundleHash"].is_string())
            c.bundle = continuData["bundleHash"].get<std::string>();
        // (the validator does not return a timestamp for ContinuId)

        continuId = c;
    }
}

// ResponseCreateToken implementation
bool ResponseCreateToken::isCreated() const {
    // createToken submits a ProposeMolecule (C-isotope token-creation), so the response is
    // ProposeMolecule-shaped — success == the molecule was accepted by the ledger.
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("status")) {
        const std::string status = data["ProposeMolecule"]["status"];
        return status == "accepted" || status == "success";
    }
    return false;
}

// The slug + amount are not in the ProposeMolecule response shape — createToken stores them
// from its args via setTokenSlug/setAmount (see KnishIOClient::createToken).
std::string ResponseCreateToken::getTokenSlug() const {
    return tokenSlug_;
}

std::string ResponseCreateToken::getAmount() const {
    return amount_.empty() ? "0" : amount_;
}

// ResponseTransferTokens implementation
// Vestigial: transferToken/burnToken return ResponseProposeMolecule (nothing builds this class).
// Kept correct-if-used by reading the real ProposeMolecule shape rather than a never-present
// data.TransferTokens object.
bool ResponseTransferTokens::isTransferred() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("status")
        && data["ProposeMolecule"]["status"].is_string()) {
        const std::string status = data["ProposeMolecule"]["status"].get<std::string>();
        return status == "accepted" || status == "success";
    }
    return false;
}

std::string ResponseTransferTokens::getTransactionHash() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("molecularHash")
        && data["ProposeMolecule"]["molecularHash"].is_string()) {
        return data["ProposeMolecule"]["molecularHash"].get<std::string>();
    }
    return "";
}

std::string ResponseTransferTokens::getAmount() const {
    // The ProposeMolecule response shape carries no transfer amount. Honest default.
    return "0";
}

// ResponseRequestAuthorization implementation
// The JWT + pubkey are in data.ProposeMolecule.payload (a stringified JSON), NOT in a
// data.RequestAuthorization object — the validator returns every op as a ProposeMolecule.
std::string ResponseRequestAuthorization::getAuthToken() const {
    const auto payload = parseProposePayload(data);
    if (payload.contains("token") && payload["token"].is_string()) {
        return payload["token"].get<std::string>();
    }
    return "";
}

std::string ResponseRequestAuthorization::getPublicKey() const {
    const auto payload = parseProposePayload(data);
    if (payload.contains("pubkey") && payload["pubkey"].is_string()) {
        return payload["pubkey"].get<std::string>();
    }
    return "";
}

bool ResponseRequestAuthorization::isAuthorized() const {
    return !getAuthToken().empty();
}

// ResponseProposeMolecule implementation
// All getters guard is_string(): `reason` is JSON null on an accepted molecule, and a raw
// null->std::string conversion throws (nlohmann type_error).
std::string ResponseProposeMolecule::getMolecularHash() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("molecularHash")
        && data["ProposeMolecule"]["molecularHash"].is_string()) {
        return data["ProposeMolecule"]["molecularHash"].get<std::string>();
    }
    return "";
}

std::string ResponseProposeMolecule::getStatus() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("status")
        && data["ProposeMolecule"]["status"].is_string()) {
        return data["ProposeMolecule"]["status"].get<std::string>();
    }
    return "unknown";
}

bool ResponseProposeMolecule::isAccepted() const {
    return getStatus() == "accepted" || getStatus() == "success";
}

std::string ResponseProposeMolecule::getRejectionReason() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("reason")
        && data["ProposeMolecule"]["reason"].is_string()) {
        return data["ProposeMolecule"]["reason"].get<std::string>();
    }
    return "";
}

} // namespace response
} // namespace knishio