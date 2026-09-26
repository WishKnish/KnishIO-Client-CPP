/**
 * @file proven_relogin.cpp
 * @brief A returning user's login must be signed from the identity's ContinuID pointer.
 *
 * Validator 0.5.0 marks an auth token proven only when atoms[0] of the U molecule sits at the
 * bundle's ContinuID position AND its address is the USER wallet registered there
 * (i_isotope.rs `auth_bundle_proven`). Signing every login from a fresh AUTH wallet at a random
 * position yields an unproven token, and the returning user is treated as a guest for
 * permissioned/private cells.
 *
 * `requestAuthToken` must therefore: query ContinuId(bundle, token: USER); when it returns a USER
 * wallet with a position P, sign the U molecule with the USER wallet derived from the secret at
 * P (the I atom carries previousPosition = P and a fresh USER remainder); when there is no
 * pointer, a non-USER wallet, or a different address, sign from a fresh AUTH wallet as before;
 * and when the pointer-signed proposal is rejected, fall back to the AUTH path exactly once, so
 * one login sends at most two authorization molecules (testnet allows 3 auths/min/IP).
 *
 * The client has no transport seam, so the transport is stubbed at the socket: a loopback HTTP
 * server answers the ContinuId query and the ProposeMolecule mutations from a script and records
 * every request the real client sends.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "response/Response.h"
#include "third_party/nlohmann/json.hpp"

using nlohmann::json;

namespace {

int failures = 0;

void check(bool ok, const std::string& name, const std::string& detail = {}) {
    std::cout << (ok ? "  \033[0;32mPASS\033[0m " : "  \033[0;31mFAIL\033[0m ") << name;
    if (!ok && !detail.empty()) {
        std::cout << "\n       " << detail;
    }
    std::cout << std::endl;
    if (!ok) {
        ++failures;
    }
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

/**
 * Loopback GraphQL stub. One request per connection (it answers `Connection: close`), so the
 * client's pooled curl handle reconnects for each call.
 */
class StubValidator {
public:
    StubValidator() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0
            || ::listen(listenFd_, 16) != 0) {
            throw std::runtime_error("stub validator: cannot listen on loopback");
        }
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
    }

    ~StubValidator() {
        stopping_ = true;
        // Unblock accept() with a throwaway connection.
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port_);
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::close(fd);
        thread_.join();
        ::close(listenFd_);
    }

    [[nodiscard]] std::string uri() const {
        return "http://127.0.0.1:" + std::to_string(port_) + "/graphql";
    }

    // The ContinuId object to answer with (json null = the bundle has no pointer).
    void setContinuId(json continuId) {
        std::lock_guard<std::mutex> lock(mutex_);
        continuId_ = std::move(continuId);
    }

    // Answer ContinuId with an HTTP error instead (a transport failure).
    void failContinuId(int httpStatus) {
        std::lock_guard<std::mutex> lock(mutex_);
        continuIdHttpStatus_ = httpStatus;
    }

    // Statuses for successive ProposeMolecule mutations ("accepted" / "rejected").
    void scriptProposals(std::deque<std::string> statuses) {
        std::lock_guard<std::mutex> lock(mutex_);
        proposeStatuses_ = std::move(statuses);
    }

    [[nodiscard]] std::vector<json> continuIdQueries() const { return byOperation("ContinuId"); }
    [[nodiscard]] std::vector<json> proposals() const { return byOperation("ProposeMolecule"); }

private:
    [[nodiscard]] std::vector<json> byOperation(const std::string& name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<json> out;
        for (const auto& r : requests_) {
            const std::string q = r.value("query", "");
            const auto brace = q.find('{');
            if (brace != std::string::npos && q.find(name, brace) != std::string::npos
                && q.find(name, brace) < q.find('(', brace)) {
                out.push_back(r);
            }
        }
        return out;
    }

    void serve() {
        while (true) {
            int fd = ::accept(listenFd_, nullptr, nullptr);
            if (stopping_) {
                if (fd >= 0) ::close(fd);
                return;
            }
            if (fd < 0) continue;
            handle(fd);
            ::close(fd);
        }
    }

    static bool sendAll(int fd, const std::string& data) {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t n = ::send(fd, data.data() + sent, data.size() - sent, 0);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    void handle(int fd) {
        std::string buf;
        char chunk[8192];
        size_t headerEnd = std::string::npos;
        while ((headerEnd = buf.find("\r\n\r\n")) == std::string::npos) {
            ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return;
            buf.append(chunk, static_cast<size_t>(n));
        }
        const std::string headers = lower(buf.substr(0, headerEnd));
        size_t contentLength = 0;
        const auto cl = headers.find("content-length:");
        if (cl != std::string::npos) {
            contentLength = std::stoul(headers.substr(cl + 15));
        }
        if (headers.find("expect: 100-continue") != std::string::npos) {
            if (!sendAll(fd, "HTTP/1.1 100 Continue\r\n\r\n")) return;
        }
        std::string body = buf.substr(headerEnd + 4);
        while (body.size() < contentLength) {
            ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return;
            body.append(chunk, static_cast<size_t>(n));
        }

        int status = 200;
        std::string reply;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            json request = json::parse(body, nullptr, false);
            if (request.is_discarded()) request = json::object();
            requests_.push_back(request);
            const std::string query = request.value("query", "");
            if (query.find("ContinuId") != std::string::npos) {
                if (continuIdHttpStatus_ != 0) {
                    status = continuIdHttpStatus_;
                    reply = R"({"errors":[{"message":"stub transport failure"}]})";
                } else {
                    reply = json{{"data", {{"ContinuId", continuId_}}}}.dump();
                }
            } else if (query.find("ProposeMolecule") != std::string::npos) {
                std::string verdict = "rejected";
                if (!proposeStatuses_.empty()) {
                    verdict = proposeStatuses_.front();
                    proposeStatuses_.pop_front();
                }
                ++proposalCount_;
                json pm = {{"molecularHash", "stub-hash-" + std::to_string(proposalCount_)},
                           {"status", verdict},
                           {"createdAt", "0"}};
                if (verdict == "accepted") {
                    pm["reason"] = nullptr;
                    pm["payload"] = json{{"token", "stub-jwt-" + std::to_string(proposalCount_)},
                                         {"key", "stub-validator-key"}}
                                        .dump();
                } else {
                    pm["reason"] = "stub rejection " + std::to_string(proposalCount_);
                    pm["payload"] = nullptr;
                }
                reply = json{{"data", {{"ProposeMolecule", pm}}}}.dump();
            } else {
                reply = R"({"data":null})";
            }
        }
        std::string response = "HTTP/1.1 " + std::to_string(status)
                               + (status == 200 ? " OK" : " Error") + "\r\n"
                               + "Content-Type: application/json\r\n"
                               + "Content-Length: " + std::to_string(reply.size()) + "\r\n"
                               + "Connection: close\r\n\r\n" + reply;
        sendAll(fd, response);
    }

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread thread_;

    mutable std::mutex mutex_;
    std::vector<json> requests_;
    json continuId_ = nullptr;
    int continuIdHttpStatus_ = 0;
    std::deque<std::string> proposeStatuses_;
    int proposalCount_ = 0;
};

std::unique_ptr<knishio::KnishIOClient> clientFor(const StubValidator& stub) {
    return knishio::KnishIOClient::Builder()
        .uris({stub.uri()})
        .cellSlug("public")
        .maxRetries(0)
        .timeout(std::chrono::milliseconds(10000))
        .enableLogging()
        .build();
}

std::string randomPosition() {
    return knishio::KnishIOClient::generateSecret(64);
}

std::optional<std::string> metaValue(const json& atom, const std::string& key) {
    if (!atom.contains("meta") || !atom["meta"].is_array()) return std::nullopt;
    for (const auto& kv : atom["meta"]) {
        if (kv.value("key", "") == key && kv.contains("value") && kv["value"].is_string()) {
            return kv["value"].get<std::string>();
        }
    }
    return std::nullopt;
}

json atomOf(const json& proposal, size_t index) {
    const auto& atoms = proposal["variables"]["molecule"]["atoms"];
    return atoms.is_array() && atoms.size() > index ? atoms[index] : json::object();
}

std::string str(const json& atom, const std::string& key) {
    return atom.contains(key) && atom[key].is_string() ? atom[key].get<std::string>() : "";
}

json userPointer(const std::string& secret, const std::string& position) {
    KnishIO::Wallet wallet(secret, "USER", position);
    return {{"position", position},
            {"address", wallet.address},
            {"tokenSlug", "USER"},
            {"bundleHash", wallet.bundle},
            {"pubkey", nullptr},
            {"characters", "BASE64"}};
}

void pointerSignedLogin() {
    std::cout << "\nReturning user: ContinuID pointer P → one USER-signed U molecule at P\n";
    StubValidator stub;
    const std::string secret = knishio::KnishIOClient::generateSecret();
    const std::string position = randomPosition();
    const KnishIO::Wallet expected(secret, "USER", position);
    stub.setContinuId(userPointer(secret, position));
    stub.scriptProposals({"accepted"});

    auto client = clientFor(stub);
    auto result = client->requestAuthToken(secret, std::nullopt, false).get();

    const auto queries = stub.continuIdQueries();
    check(!queries.empty() && queries.front()["variables"].value("token", "") == "USER",
          "the ContinuId query is sent with token USER",
          queries.empty() ? "no ContinuId query was sent" : queries.front().dump());
    check(!queries.empty() && queries.front()["variables"].value("bundle", "") == expected.bundle,
          "the ContinuId query names the secret's bundle");

    const auto proposals = stub.proposals();
    check(proposals.size() == 1, "exactly one authorization molecule is proposed",
          "proposals: " + std::to_string(proposals.size()));
    if (proposals.empty()) return;
    const json u = atomOf(proposals.front(), 0);
    const json i = atomOf(proposals.front(), 1);
    check(str(u, "isotope") == "U", "atoms[0] is the U isotope", str(u, "isotope"));
    check(str(u, "token") == "USER", "atoms[0] is signed with token USER", str(u, "token"));
    check(str(u, "position") == position, "atoms[0] sits at the ContinuID position P", str(u, "position"));
    check(str(u, "walletAddress") == expected.address,
          "atoms[0] address is the USER wallet derived from the secret at P", str(u, "walletAddress"));
    check(metaValue(u, "walletPubkey").value_or("").size() > 0,
          "atoms[0] still carries the signed walletPubkey meta");
    check(str(i, "isotope") == "I" && str(i, "token") == "USER",
          "atoms[1] is the USER ContinuID atom", str(i, "isotope") + "/" + str(i, "token"));
    check(metaValue(i, "previousPosition").value_or("") == position,
          "atoms[1].meta.previousPosition == P", metaValue(i, "previousPosition").value_or("(absent)"));
    check(!str(i, "position").empty() && str(i, "position") != position,
          "atoms[1] moves the pointer to a fresh USER position", str(i, "position"));
    check(result->isAuthorized() && client->isAuthenticated(),
          "the pointer-signed token is bound to the session");

    // The client's own verifier must accept the USER-signed auth molecule (it has no U-token rule;
    // the OTS check recovers the signer's address and compares it with atoms[0].walletAddress).
    const auto molecule = KnishIO::Molecule::jsonToObject(proposals.front()["variables"]["molecule"].dump());
    check(KnishIO::Molecule::verify(molecule), "Molecule::verify accepts the USER-signed auth molecule");
}

void authPathWhen(const std::string& label, const json& continuId) {
    std::cout << "\n" << label << " → one AUTH-signed U molecule (today's path)\n";
    StubValidator stub;
    const std::string secret = knishio::KnishIOClient::generateSecret();
    stub.setContinuId(continuId.is_null() ? json(nullptr) : continuId);
    stub.scriptProposals({"accepted"});

    auto client = clientFor(stub);
    auto result = client->requestAuthToken(secret, std::nullopt, false).get();

    const auto proposals = stub.proposals();
    check(proposals.size() == 1, "exactly one authorization molecule is proposed",
          "proposals: " + std::to_string(proposals.size()));
    if (proposals.empty()) return;
    check(str(atomOf(proposals.front(), 0), "token") == "AUTH", "atoms[0] is signed with token AUTH",
          str(atomOf(proposals.front(), 0), "token"));
    check(result->isAuthorized() && client->isAuthenticated(), "the AUTH token is bound to the session");
}

void noPointerCases() {
    const std::string other = knishio::KnishIOClient::generateSecret();
    const std::string position = randomPosition();

    authPathWhen("Genesis: ContinuId returns null", nullptr);

    json emptyPosition = userPointer(other, position);
    emptyPosition["position"] = "";
    authPathWhen("ContinuId returns an empty position", emptyPosition);

    json nonUser = userPointer(other, position);
    nonUser["tokenSlug"] = "AUTH";
    authPathWhen("ContinuId returns a non-USER wallet", nonUser);

    // A USER pointer whose address is not the one this secret derives at P (another identity's
    // wallet): signing there would be rejected, so do not spend an auth on it.
    authPathWhen("ContinuId returns a USER wallet with a different address", userPointer(other, position));
}

void rejectedPointerFallsBackOnce(const std::string& fallbackVerdict) {
    const bool fallbackAccepted = fallbackVerdict == "accepted";
    std::cout << "\nPointer-signed login rejected, fallback " << fallbackVerdict
              << " → exactly two molecules\n";
    StubValidator stub;
    const std::string secret = knishio::KnishIOClient::generateSecret();
    const std::string position = randomPosition();
    stub.setContinuId(userPointer(secret, position));
    stub.scriptProposals({"rejected", fallbackVerdict, "accepted"});

    auto client = clientFor(stub);
    auto result = client->requestAuthToken(secret, std::nullopt, false).get();

    const auto proposals = stub.proposals();
    check(proposals.size() == 2, "exactly two authorization molecules are proposed",
          "proposals: " + std::to_string(proposals.size()));
    check(stub.continuIdQueries().size() == 1, "the pointer is queried once, not retried",
          "ContinuId queries: " + std::to_string(stub.continuIdQueries().size()));
    if (proposals.size() < 2) return;
    check(str(atomOf(proposals[0], 0), "token") == "USER", "the first molecule is pointer-signed (USER)",
          str(atomOf(proposals[0], 0), "token"));
    check(str(atomOf(proposals[1], 0), "token") == "AUTH", "the second molecule is the AUTH fallback",
          str(atomOf(proposals[1], 0), "token"));
    if (fallbackAccepted) {
        check(result->isAuthorized() && client->isAuthenticated(),
              "the fallback's AUTH token is bound to the session");
    } else {
        // C++ reports a rejected authorization in the returned response, not with an exception:
        // the fallback's rejection comes back exactly as today's single-path rejection did.
        knishio::response::ResponseProposeMolecule view;
        view.setData(result->getData());
        check(!result->isAuthorized() && !client->isAuthenticated() && view.getStatus() == "rejected"
                  && view.getRejectionReason() == "stub rejection 2",
              "the fallback's rejection is returned as the authorization result",
              result->getData().dump());
    }
}

void continuIdTransportErrorPropagates() {
    std::cout << "\nContinuId transport error → no authorization molecule, error returned\n";
    StubValidator stub;
    stub.failContinuId(500);
    stub.scriptProposals({"accepted"});

    auto client = clientFor(stub);
    auto result = client->requestAuthToken(knishio::KnishIOClient::generateSecret(), std::nullopt, false).get();

    check(stub.proposals().empty(), "no authorization molecule is proposed",
          "proposals: " + std::to_string(stub.proposals().size()));
    check(result->getError().has_value() && !client->isAuthenticated(),
          "the query failure is returned as the authorization error",
          result->getError().value_or("(no error)"));
}

}  // namespace

int main() {
    std::cout << "Proven re-login: sign a returning user's auth from the ContinuID pointer\n";
    try {
        pointerSignedLogin();
        noPointerCases();
        rejectedPointerFallsBackOnce("accepted");
        rejectedPointerFallsBackOnce("rejected");
        continuIdTransportErrorPropagates();
    } catch (const std::exception& e) {
        check(false, "no unexpected exception", e.what());
    }
    std::cout << (failures == 0 ? "\nAll checks passed\n" : "\nFailures: " + std::to_string(failures) + "\n");
    return failures == 0 ? 0 : 1;
}
