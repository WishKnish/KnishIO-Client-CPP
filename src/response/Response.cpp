#include "response/Response.h"

namespace knishio {
namespace response {

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
        
        if (balanceData.contains("characters") && balanceData["characters"].is_array()) {
            for (const auto& ch : balanceData["characters"]) {
                b.characters.push_back(ch);
            }
        }
        
        balance = b;
    }
}

// ResponseWalletList implementation
void ResponseWalletList::parseData() {
    wallets.clear();
    
    if (data.contains("WalletList") && data["WalletList"].is_array()) {
        for (const auto& walletData : data["WalletList"]) {
            Wallet w;
            
            if (walletData.contains("address")) w.address = walletData["address"];
            if (walletData.contains("bundleHash")) w.bundleHash = walletData["bundleHash"];
            if (walletData.contains("token")) w.token = walletData["token"];
            if (walletData.contains("position")) w.position = walletData["position"];
            if (walletData.contains("pubkey")) w.pubkey = walletData["pubkey"];
            if (walletData.contains("balance")) w.balance = walletData["balance"];
            
            wallets.push_back(w);
        }
    }
}

// ResponseContinuId implementation
void ResponseContinuId::parseData() {
    if (data.contains("ContinuId") && !data["ContinuId"].is_null()) {
        ContinuID c;
        auto continuData = data["ContinuId"];
        
        if (continuData.contains("bundle")) c.bundle = continuData["bundle"];
        if (continuData.contains("position")) c.position = continuData["position"];
        if (continuData.contains("walletAddress")) c.walletAddress = continuData["walletAddress"];
        if (continuData.contains("timestamp")) c.timestamp = continuData["timestamp"];
        
        continuId = c;
    }
}

// ResponseCreateToken implementation
bool ResponseCreateToken::isCreated() const {
    return data.contains("CreateToken") && 
           data["CreateToken"].contains("success") && 
           data["CreateToken"]["success"] == true;
}

std::string ResponseCreateToken::getTokenSlug() const {
    if (data.contains("CreateToken") && data["CreateToken"].contains("tokenSlug")) {
        return data["CreateToken"]["tokenSlug"];
    }
    return "";
}

std::string ResponseCreateToken::getAmount() const {
    if (data.contains("CreateToken") && data["CreateToken"].contains("amount")) {
        return data["CreateToken"]["amount"];
    }
    return "0";
}

// ResponseTransferTokens implementation
bool ResponseTransferTokens::isTransferred() const {
    return data.contains("TransferTokens") && 
           data["TransferTokens"].contains("success") && 
           data["TransferTokens"]["success"] == true;
}

std::string ResponseTransferTokens::getTransactionHash() const {
    if (data.contains("TransferTokens") && data["TransferTokens"].contains("transactionHash")) {
        return data["TransferTokens"]["transactionHash"];
    }
    return "";
}

std::string ResponseTransferTokens::getAmount() const {
    if (data.contains("TransferTokens") && data["TransferTokens"].contains("amount")) {
        return data["TransferTokens"]["amount"];
    }
    return "0";
}

// ResponseRequestAuthorization implementation
std::string ResponseRequestAuthorization::getAuthToken() const {
    if (data.contains("RequestAuthorization") && data["RequestAuthorization"].contains("token")) {
        return data["RequestAuthorization"]["token"];
    }
    return "";
}

std::string ResponseRequestAuthorization::getPublicKey() const {
    if (data.contains("RequestAuthorization") && data["RequestAuthorization"].contains("pubkey")) {
        return data["RequestAuthorization"]["pubkey"];
    }
    return "";
}

bool ResponseRequestAuthorization::isAuthorized() const {
    return !getAuthToken().empty();
}

// ResponseProposeMolecule implementation
std::string ResponseProposeMolecule::getMolecularHash() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("molecularHash")) {
        return data["ProposeMolecule"]["molecularHash"];
    }
    return "";
}

std::string ResponseProposeMolecule::getStatus() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("status")) {
        return data["ProposeMolecule"]["status"];
    }
    return "unknown";
}

bool ResponseProposeMolecule::isAccepted() const {
    return getStatus() == "accepted" || getStatus() == "success";
}

std::string ResponseProposeMolecule::getRejectionReason() const {
    if (data.contains("ProposeMolecule") && data["ProposeMolecule"].contains("reason")) {
        return data["ProposeMolecule"]["reason"];
    }
    return "";
}

} // namespace response
} // namespace knishio