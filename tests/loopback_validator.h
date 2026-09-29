/**
 * @file loopback_validator.h
 * @brief A loopback GraphQL validator stub for driving the public client operations offline.
 *
 * The client has no transport seam, so the tests (tests/phaseb_molecules.cpp and the
 * self-test's create_token_units vectors) point a real KnishIOClient at this stub on 127.0.0.1
 * and read back the molecules it proposed. It answers ContinuId, Balance and ProposeMolecule
 * (always "accepted"); every other query gets {"data":null}. POSIX sockets only.
 */
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "KnishIOClient.h"
#include "Wallet.h"
#include "response/Response.h"
#include "third_party/nlohmann/json.hpp"

namespace knishio_test {

using nlohmann::json;

inline std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

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

    StubValidator(const StubValidator&) = delete;
    StubValidator& operator=(const StubValidator&) = delete;

    [[nodiscard]] std::string uri() const { return "http://127.0.0.1:" + std::to_string(port_) + "/graphql"; }

    void setContinuId(json continuId) { std::lock_guard<std::mutex> lock(mutex_); continuId_ = std::move(continuId); }
    void setBalance(json regular, json buffer = nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        regular_ = std::move(regular);
        buffer_ = std::move(buffer);
    }

    [[nodiscard]] std::vector<json> requests(const std::string& operation) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<json> out;
        for (const auto& r : requests_) {
            if (r.value("query", "").find(operation) != std::string::npos) out.push_back(r);
        }
        return out;
    }

private:
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
        if (cl != std::string::npos) contentLength = std::stoul(headers.substr(cl + 15));
        if (headers.find("expect: 100-continue") != std::string::npos) {
            if (!sendAll(fd, "HTTP/1.1 100 Continue\r\n\r\n")) return;
        }
        std::string body = buf.substr(headerEnd + 4);
        while (body.size() < contentLength) {
            ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) return;
            body.append(chunk, static_cast<size_t>(n));
        }

        std::string reply;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            json request = json::parse(body, nullptr, false);
            if (request.is_discarded()) request = json::object();
            requests_.push_back(request);
            const std::string query = request.value("query", "");
            if (query.find("ContinuId") != std::string::npos) {
                reply = json{{"data", {{"ContinuId", continuId_}}}}.dump();
            } else if (query.find("Balance") != std::string::npos) {
                const json vars = request.value("variables", json::object());
                const bool buffer = vars.contains("type") && vars["type"] == "buffer";
                reply = json{{"data", {{"Balance", buffer ? buffer_ : regular_}}}}.dump();
            } else if (query.find("ProposeMolecule") != std::string::npos) {
                ++proposals_;
                json pm = {{"molecularHash", "stub-hash-" + std::to_string(proposals_)},
                           {"status", "accepted"},
                           {"reason", nullptr},
                           {"createdAt", "0"},
                           {"payload", json{{"token", "stub-jwt"}, {"key", "stub-validator-key"}}.dump()}};
                reply = json{{"data", {{"ProposeMolecule", pm}}}}.dump();
            } else {
                reply = R"({"data":null})";
            }
        }
        sendAll(fd, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                        + std::to_string(reply.size()) + "\r\nConnection: close\r\n\r\n" + reply);
    }

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread thread_;
    mutable std::mutex mutex_;
    std::vector<json> requests_;
    json continuId_ = nullptr;
    json regular_ = nullptr;
    json buffer_ = nullptr;
    int proposals_ = 0;
};

// A client logged in to its own stub (the login is an AUTH molecule the stub accepts).
struct Session {
    StubValidator stub;
    std::string secret = knishio::KnishIOClient::generateSecret();
    std::unique_ptr<knishio::KnishIOClient> client;
    std::string bundle;

    Session() {
        client = knishio::KnishIOClient::Builder().uris({stub.uri()}).cellSlug("public").maxRetries(0)
                     .timeout(std::chrono::milliseconds(10000)).build();
        (void)client->requestAuthToken(secret).get();   // no pointer yet: AUTH login, stub issues a token
        bundle = KnishIO::Wallet::generateBundleHash(secret);
    }

    // After login the bundle's ContinuID pointer is the USER wallet at `position`.
    void pointAt(const std::string& position) {
        KnishIO::Wallet user(secret, "USER", position);
        stub.setContinuId({{"position", position}, {"address", user.address}, {"tokenSlug", "USER"},
                           {"bundleHash", bundle}, {"pubkey", nullptr}, {"characters", "BASE64"}});
    }

    [[nodiscard]] json balanceRow(const std::string& token, const std::string& position, const std::string& amount,
                                  const std::string& batchId, const std::vector<std::string>& units = {}) const {
        KnishIO::Wallet wallet(secret, token, position);
        json unitRows = json::array();
        for (const auto& id : units) unitRows.push_back({{"id", id}, {"name", id}, {"metas", json::object()}});
        return {{"position", position}, {"address", wallet.address}, {"tokenSlug", token}, {"amount", amount},
                {"pubkey", nullptr}, {"batchId", batchId.empty() ? json(nullptr) : json(batchId)},
                {"bundleHash", bundle}, {"tokenUnits", unitRows}};
    }

    // The molecules the client proposed after the login.
    [[nodiscard]] std::vector<json> built() const {
        auto all = stub.requests("ProposeMolecule");
        all.erase(all.begin());   // the login
        return all;
    }
};

}  // namespace knishio_test
