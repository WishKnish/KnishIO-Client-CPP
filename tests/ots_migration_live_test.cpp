// Live OTS version migration against a running validator: a client set to otsVersion 2 moves an
// identity whose ContinuID head is v1 to v2, and a later otsVersion 1 client keeps it at v2.
//
// Gated on OTS_MIGRATION_TEST_URL: unset, it exits 77, which ctest reports as Skipped
// (SKIP_RETURN_CODE in tests/CMakeLists.txt). Prints one PASS line per step and exits 0 only when
// all four pass. Run live:
//   OTS_MIGRATION_TEST_URL=http://localhost:8080/graphql ./build/tests/ots_migration_live_test
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>

#include "KnishIOClient.h"
#include "Wallet.h"
#include "response/Response.h"

namespace {

struct Head {
    std::string position;
    std::string address;
};

std::unique_ptr<knishio::KnishIOClient> clientAt(const std::string& url, int otsVersion) {
    return knishio::KnishIOClient::Builder()
        .uris({url})
        .timeout(std::chrono::milliseconds(15000))
        .otsVersion(otsVersion)
        .build();
}

void login(knishio::KnishIOClient& client, const std::string& secret) {
    auto result = client.requestAuthToken(secret, std::optional<std::string>("public"), false).get();
    if (!result || !result->isAuthorized()) {
        throw std::runtime_error("login was not authorized");
    }
}

Head head(knishio::KnishIOClient& client, const std::string& bundle) {
    auto response = client.queryContinuId(bundle).get();
    const auto continuId = response ? response->getContinuId() : std::nullopt;
    if (!continuId.has_value() || continuId->position.empty() || continuId->walletAddress.empty()) {
        throw std::runtime_error("no ContinuID head");
    }
    return {continuId->position, continuId->walletAddress};
}

int version(const std::string& secret, const Head& h) {
    return KnishIO::Wallet::detectOtsVersion(secret, "USER", h.position, h.address, 1).value_or(0);
}

int fail(const std::string& step, const std::string& detail) {
    std::cout << "FAIL: " << step << " " << detail << "\n";
    return 1;
}

}  // namespace

int main() {
    const char* envUrl = std::getenv("OTS_MIGRATION_TEST_URL");
    if (envUrl == nullptr || std::string(envUrl).empty()) {
        std::cout << "SKIP: OTS_MIGRATION_TEST_URL not set — skipping live OTS migration test\n";
        return 77;  // ctest SKIP_RETURN_CODE: reported as Skipped, never as Passed
    }
    const std::string url(envUrl);
    std::string step = "1";

    try {
        const std::string secret = knishio::KnishIOClient::generateSecret(2048);
        const std::string bundle = KnishIO::Wallet::generateBundleHash(secret);

        step = "2";
        auto a = clientAt(url, 1);
        login(*a, secret);
        const Head h1 = head(*a, bundle);
        if (version(secret, h1) != 1) {
            return fail(step, "v1 login head is version " + std::to_string(version(secret, h1)));
        }
        std::cout << "PASS: 2 v1 login leaves a v1 head\n";

        step = "3";
        auto b = clientAt(url, 2);
        login(*b, secret);
        const Head h2 = head(*b, bundle);
        if (h2.position == h1.position) {
            return fail(step, "head position unchanged");
        }
        if (version(secret, h2) != 2) {
            return fail(step, "head is version " + std::to_string(version(secret, h2)));
        }
        std::cout << "PASS: 3 v2 login moves the head to v2\n";

        step = "4";
        const std::string metaId = "ots-migration-cpp-"
            + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        auto meta = b->createMeta("ots-migration", metaId, {{"step", "4"}}).get();
        if (!meta || !meta->isAccepted()) {
            return fail(step, "createMeta rejected: " + (meta ? meta->getRejectionReason() : std::string("no response")));
        }
        const Head h3 = head(*b, bundle);
        if (h3.position == h2.position) {
            return fail(step, "head position unchanged");
        }
        if (version(secret, h3) != 2) {
            return fail(step, "head is version " + std::to_string(version(secret, h3)));
        }
        std::cout << "PASS: 4 v2 createMeta accepted, head stays v2\n";

        step = "5";
        auto c = clientAt(url, 1);
        login(*c, secret);
        const Head h4 = head(*c, bundle);
        if (h4.position == h3.position) {
            return fail(step, "head position unchanged");
        }
        if (version(secret, h4) != 2) {
            return fail(step, "head is version " + std::to_string(version(secret, h4)));
        }
        std::cout << "PASS: 5 v1 login keeps the head at v2\n";
        return 0;
    } catch (const std::exception& e) {
        return fail(step, std::string("exception: ") + e.what());
    }
}
