/**
 * @file ots_v2_vectors.cpp
 * @brief OTS v2 (64-chain WOTS+): key derivation, address, normalized hash, ML-KEM identities
 *        of v2 wallets, molecule verdicts and malformed declared hashes.
 *
 * Three modes, registered as three CTest entries:
 *   - `roundtrip` (OtsV2RoundTrip): always runs. A v2 source wallet signs a molecule, the
 *     5464-char signature verifies, and one flipped character gives SignatureMismatchException.
 *   - `client` (OtsV2Client): always runs. Client-level OTS version: the Builder option, version
 *     detection, Wallet::setOtsVersion, and the wallets a client signs from, against the loopback
 *     stub validator (tests/loopback_validator.h).
 *   - `vectors` (OtsV2Vectors): the shared OTS v2 vectors, read from KNISHIO_OTS_V2_VECTORS or
 *     ../shared-test-results/ots-v2-vectors.json. A standalone checkout has no such file; the
 *     test then prints SKIP and exits 77, which CTest reports as skipped.
 */
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "utility.h"
#include "exception/KnishIOException.h"
#include "loopback_validator.h"
#include "third_party/nlohmann/json.hpp"

using json = nlohmann::json;
using KnishIO::Molecule;
using KnishIO::Wallet;

namespace knishio {
// Declared a friend of KnishIOClient: reaches the private ledger-wallet binding helper.
class KnishIOClientTestAccess {
public:
    static int bind(const KnishIOClient& client, const std::string& token, const std::string& position,
                    const std::string& address) {
        return client.bindOwnWalletOtsVersion(token, position, address);
    }
};
}  // namespace knishio

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

// Names the outcome of a throwing verification call: "ok", "SignatureMalformed",
// "SignatureMismatch", or the text of any other exception.
template <typename F>
std::string outcome(F&& call) {
    try {
        call();
        return "ok";
    } catch (const knishio::SignatureMalformedException&) {
        return "SignatureMalformed";
    } catch (const knishio::SignatureMismatchException&) {
        return "SignatureMismatch";
    } catch (const std::exception& e) {
        return std::string("threw: ") + e.what();
    }
}

std::string joinFragments(const Molecule& molecule) {
    std::string joined;
    for (const auto& atom : molecule.atoms) {
        joined += atom.otsFragment;
    }
    return joined;
}

int runRoundTrip() {
    std::cout << "OTS v2 sign / verify round trip" << std::endl;

    std::string secret;
    for (int i = 0; i < 128; i++) {
        secret += "0123456789abcdef";
    }
    const std::string position(64, 'a');
    const std::vector<std::pair<std::string, std::string>> meta = {{"sample", "7"}};

    try {
        Wallet source(secret, "USER", position, 64, 1024, 2);
        Wallet remainder(secret, "USER", "", 64, 1024, source.ots_version);
        check(source.ots_version == 2 && source.key.size() == 8192, "a v2 wallet holds an 8192-hex key",
              "version " + std::to_string(source.ots_version) + ", key " + std::to_string(source.key.size()));
        check(remainder.ots_version == 2, "a remainder built at the source's version is v2");

        Molecule mol("");
        mol.sourceWallet = std::make_shared<Wallet>(source);
        mol.remainderWallet = std::make_shared<Wallet>(remainder);
        mol.initMeta(source, meta, "OtsV2", "round-trip");
        check(mol.signingOtsVersion() == 2, "signingOtsVersion() follows the source wallet");
        mol.sign(secret);

        const std::string joined = joinFragments(mol);
        check(joined.size() == 5464, "the compressed v2 signature is 5464 characters",
              "got " + std::to_string(joined.size()));
        const std::string verdict = outcome([&] { Molecule::check(mol); });
        check(verdict == "ok", "Molecule::check() accepts the v2 molecule", verdict);
        check(Molecule::verify(mol), "Molecule::verify() accepts the v2 molecule");

        Molecule tampered = mol;
        std::string& fragment = tampered.atoms.front().otsFragment;
        const auto at = fragment.find_first_of("AB");
        check(at != std::string::npos, "atoms[0].otsFragment has an A or B to flip");
        if (at != std::string::npos) {
            fragment[at] = fragment[at] == 'A' ? 'B' : 'A';
            const std::string tamperedVerdict = outcome([&] { Molecule::check(tampered); });
            check(tamperedVerdict == "SignatureMismatch",
                  "one flipped character gives SignatureMismatchException", tamperedVerdict);
            check(!Molecule::verify(tampered), "Molecule::verify() returns false for it");
        }
    } catch (const std::exception& e) {
        check(false, "round trip", std::string("threw: ") + e.what());
    }

    try {
        Wallet unsupported("abcdef", "USER", "", 64, 1024, 3);
        check(false, "an unsupported OTS version is refused", "constructed a wallet");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 3; expected 1 or 2.",
              "an unsupported OTS version is refused", e.what());
    }

    return failures == 0 ? 0 : 1;
}

// The WOTS+ address computed the long way: each 128-hex chunk hashed 16 times, then
// SHAKE256 to 8192 bits and SHAKE256 to 256 bits. Independent of the build's kcore option.
std::string referenceAddress(const std::string& key) {
    std::string digest;
    for (size_t at = 0; at < key.size(); at += 128) {
        std::string chunk = key.substr(at, 128);
        for (int i = 0; i < 16; i++) {
            chunk = shake256Hex(chunk, 512);
        }
        digest += chunk;
    }
    return shake256Hex(shake256Hex(digest, 8192), 256);
}

// Wallet::generateWalletAddress equals the reference address for v1 and v2 keys, including
// keys the address entry point does not take as-is (uppercase hex).
int runAddress() {
    std::cout << "WOTS+ address equals the reference for v1 and v2 keys" << std::endl;
    std::string secret;
    for (int i = 0; i < 128; i++) {
        secret += "0123456789abcdef";
    }
    for (int n = 0; n < 20; n++) {
        std::string position(64, '0');
        const std::string suffix = std::to_string(n);
        position.replace(64 - suffix.size(), suffix.size(), suffix);
        for (int version = 1; version <= 2; version++) {
            const std::string key = Wallet::generateWalletKey(secret, "USER", position, version);
            const std::string name = "v" + std::to_string(version) + " position " + suffix;
            check(Wallet::generateWalletAddress(key) == referenceAddress(key), name + ": address");
        }
    }
    std::string upper = Wallet::generateWalletKey(secret, "USER", std::string(64, 'f'), 2);
    for (auto& c : upper) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    check(Wallet::generateWalletAddress(upper) == referenceAddress(upper), "v2 uppercase key: address");
    return failures == 0 ? 0 : 1;
}

bool endsWith(const std::string& text, const std::string& suffix) {
    return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string joinedSignature(const json& proposal) {
    std::string joined;
    for (const auto& atom : proposal["variables"]["molecule"]["atoms"]) {
        if (atom.contains("otsFragment") && atom["otsFragment"].is_string()) {
            joined += atom["otsFragment"].get<std::string>();
        }
    }
    return joined;
}

std::string atomString(const json& atom, const std::string& field) {
    return atom.contains(field) && atom[field].is_string() ? atom[field].get<std::string>() : std::string();
}

std::string metaString(const json& atom, const std::string& key) {
    if (atom.contains("meta") && atom["meta"].is_array()) {
        for (const auto& kv : atom["meta"]) {
            if (kv.value("key", "") == key && kv["value"].is_string()) {
                return kv["value"].get<std::string>();
            }
        }
    }
    return {};
}

// The OTS version whose derivation (secret, token, position) gives `address`; 0 for neither.
int versionOf(const std::string& secret, const std::string& token, const std::string& position,
              const std::string& address) {
    return Wallet::detectOtsVersion(secret, token, position, address).value_or(0);
}

// The OTS version of the wallet that signed a proposal: atoms[0]'s address derivation, and the
// signature size that version gives (1368 base64 characters for v1, 5464 for v2).
int signerVersion(const std::string& secret, const json& proposal) {
    const json& first = proposal["variables"]["molecule"]["atoms"][0];
    const int version = versionOf(secret, atomString(first, "token"), atomString(first, "position"),
                                  atomString(first, "walletAddress"));
    const size_t size = joinedSignature(proposal).size();
    if ((version == 1 && size != 1368) || (version == 2 && size != 5464)) {
        return -1;
    }
    return version;
}

// The OTS version of the proposal's new ContinuID head (its I-atom, found by isotope); 0 for none.
int successorVersion(const std::string& secret, const json& proposal) {
    for (const auto& atom : proposal["variables"]["molecule"]["atoms"]) {
        if (atomString(atom, "isotope") == "I") {
            return versionOf(secret, "USER", atomString(atom, "position"), atomString(atom, "walletAddress"));
        }
    }
    return 0;
}

std::unique_ptr<knishio::KnishIOClient> clientAt(const std::string& uri, int otsVersion) {
    return knishio::KnishIOClient::Builder().uris({uri}).cellSlug("public").maxRetries(0)
        .timeout(std::chrono::milliseconds(10000)).otsVersion(otsVersion).build();
}

json continuIdAt(const std::string& bundle, const std::string& position, const std::string& address) {
    return {{"position", position}, {"address", address}, {"tokenSlug", "USER"},
            {"bundleHash", bundle}, {"pubkey", nullptr}, {"characters", "BASE64"}};
}

int runClient() {
    std::string secret;
    for (int i = 0; i < 128; i++) {
        secret += "0123456789abcdef";
    }
    const std::string position(64, 'b');
    const std::string addressV1 = Wallet::generateWalletAddress(Wallet::generateWalletKey(secret, "USER", position, 1));
    const std::string addressV2 = Wallet::generateWalletAddress(Wallet::generateWalletKey(secret, "USER", position, 2));
    const std::string unrelated(64, 'c');
    const std::string bundle = Wallet::generateBundleHash(secret);
    const std::string notDerived = "KnishIO: wallet " + unrelated + " is not derived from this secret at position "
        + position + " under OTS version 1 or 2.";

    std::cout << "Wallet::detectOtsVersion and Wallet::setOtsVersion" << std::endl;
    for (const int preferred : {1, 2}) {
        const std::string order = " (preferred " + std::to_string(preferred) + ")";
        check(Wallet::detectOtsVersion(secret, "USER", position, addressV1, preferred) == std::optional<int>(1),
              "a v1 address detects as 1" + order);
        check(Wallet::detectOtsVersion(secret, "USER", position, addressV2, preferred) == std::optional<int>(2),
              "a v2 address detects as 2" + order);
        check(!Wallet::detectOtsVersion(secret, "USER", position, unrelated, preferred).has_value(),
              "an unrelated address detects as none" + order);
    }
    std::string upperV2 = addressV2;
    for (auto& c : upperV2) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    check(Wallet::detectOtsVersion(secret, "USER", position, upperV2, 1) == std::optional<int>(2),
          "detection compares addresses case-insensitively");

    try {
        Wallet keyless(secret, "USER", position);
        keyless.key.clear();
        keyless.address = addressV2;
        check(keyless.setOtsVersion(2).ots_version == 2, "setOtsVersion sets a wallet that holds no key");
    } catch (const std::exception& e) {
        check(false, "setOtsVersion sets a wallet that holds no key", std::string("threw: ") + e.what());
    }
    Wallet keyed(secret, "USER", position);
    try {
        keyed.setOtsVersion(2);
        check(false, "setOtsVersion refuses to change a keyed wallet", "changed it");
    } catch (const std::logic_error& e) {
        check(std::string(e.what()) == "KnishIO: cannot change the OTS version of a keyed wallet.",
              "setOtsVersion refuses to change a keyed wallet", e.what());
    }
    check(keyed.setOtsVersion(1).ots_version == 1, "setOtsVersion keeps a keyed wallet's own version");

    std::cout << "\nKnishIOClient OTS version option" << std::endl;
    try {
        (void)knishio::KnishIOClient::Builder().otsVersion(3);
        check(false, "Builder::otsVersion refuses 3", "accepted it");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 3; expected 1 or 2.",
              "Builder::otsVersion refuses 3", e.what());
    }
    try {
        knishio::KnishIOClient::Config config;
        config.uris = {"http://127.0.0.1:9/graphql"};
        config.otsVersion = 0;
        knishio::KnishIOClient client(config);
        check(false, "a Config with otsVersion 0 is refused", "constructed a client");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 0; expected 1 or 2.",
              "a Config with otsVersion 0 is refused", e.what());
    }
    check(knishio::KnishIOClient::Builder().uris({"http://127.0.0.1:9/graphql"}).build()->getOtsVersion() == 2,
          "the client OTS version defaults to 2");

    try {
        std::cout << "\nA client at OTS version 2 creates v2 keys" << std::endl;
        knishio_test::StubValidator stub;
        auto client = clientAt(stub.uri(), 2);
        check(client->getOtsVersion() == 2, "getOtsVersion() returns the option");
        (void)client->requestAuthToken(secret).get();   // no ContinuID: fresh AUTH wallet
        (void)client->createMeta("OtsV2", "client", {{"k", "v"}}).get();   // no ContinuID: fresh USER source
        (void)client->createWallet("OTSV2").get();
        const auto proposals = stub.requests("ProposeMolecule");
        check(proposals.size() == 3, "three molecules proposed", "got " + std::to_string(proposals.size()));
        if (proposals.size() == 3) {
            const json& auth = proposals[0]["variables"]["molecule"]["atoms"][0];
            check(atomString(auth, "token") == "AUTH" && signerVersion(secret, proposals[0]) == 2,
                  "the AUTH login wallet is v2");
            check(signerVersion(secret, proposals[1]) == 2, "the source wallet without a ContinuID is v2");
            check(signerVersion(secret, proposals[2]) == 2, "createWallet signs from a v2 source");
            bool newWalletV2 = false;
            for (const auto& atom : proposals[2]["variables"]["molecule"]["atoms"]) {
                if (atomString(atom, "isotope") == "C") {
                    newWalletV2 = versionOf(secret, "OTSV2", metaString(atom, "walletPosition"),
                                            metaString(atom, "walletAddress")) == 2;
                }
            }
            check(newWalletV2, "createWallet defines a v2 wallet");
        }
    } catch (const std::exception& e) {
        check(false, "client at version 2", std::string("threw: ") + e.what());
    }

    try {
        std::cout << "\nA client at OTS version 1 signs from a v2 ledger wallet" << std::endl;
        knishio_test::StubValidator stub;
        stub.setContinuId(continuIdAt(bundle, position, addressV2));
        auto client = clientAt(stub.uri(), 1);
        (void)client->requestAuthToken(secret).get();   // the ContinuID pointer is a v2 USER wallet
        check(knishio::KnishIOClientTestAccess::bind(*client, "USER", position, addressV2) == 2,
              "binding a v2 ledger wallet gives 2");
        check(knishio::KnishIOClientTestAccess::bind(*client, "USER", position, addressV1) == 1,
              "binding a v1 ledger wallet gives 1");
        check(knishio::KnishIOClientTestAccess::bind(*client, "USER", position, "") == 1,
              "a wallet without an address takes the client version");
        (void)client->createMeta("OtsV2", "detect", {{"k", "v"}}).get();
        const auto proposals = stub.requests("ProposeMolecule");
        check(proposals.size() == 2, "two molecules proposed", "got " + std::to_string(proposals.size()));
        if (proposals.size() == 2) {
            const json& login = proposals[0]["variables"]["molecule"]["atoms"][0];
            check(atomString(login, "token") == "USER" && atomString(login, "walletAddress") == addressV2
                      && signerVersion(secret, proposals[0]) == 2,
                  "the login signs from the v2 ContinuID pointer");
            const json& meta = proposals[1]["variables"]["molecule"]["atoms"][0];
            check(atomString(meta, "walletAddress") == addressV2 && signerVersion(secret, proposals[1]) == 2,
                  "the source wallet at a v2 ContinuID head is v2");
            check(successorVersion(secret, proposals[0]) == 2, "the login's new ContinuID head stays v2");
            check(successorVersion(secret, proposals[1]) == 2, "createMeta's new ContinuID head stays v2");
        }
    } catch (const std::exception& e) {
        check(false, "client at version 1 with a v2 ledger wallet", std::string("threw: ") + e.what());
    }

    try {
        std::cout << "\nA client at OTS version 2 moves a v1 identity to v2\n";
        knishio_test::StubValidator stub;
        stub.setContinuId(continuIdAt(bundle, position, addressV1));
        auto client = clientAt(stub.uri(), 2);
        (void)client->requestAuthToken(secret).get();   // the ContinuID pointer is a v1 USER wallet
        (void)client->createMeta("OtsV2", "migrate", {{"k", "v"}}).get();
        const auto proposals = stub.requests("ProposeMolecule");
        check(proposals.size() == 2, "two molecules proposed", "got " + std::to_string(proposals.size()));
        if (proposals.size() == 2) {
            const json& login = proposals[0]["variables"]["molecule"]["atoms"][0];
            check(atomString(login, "walletAddress") == addressV1 && signerVersion(secret, proposals[0]) == 1,
                  "the login signs from the v1 ContinuID pointer");
            check(successorVersion(secret, proposals[0]) == 2, "the login's new ContinuID head is v2");
            const json& meta = proposals[1]["variables"]["molecule"]["atoms"][0];
            check(atomString(meta, "walletAddress") == addressV1 && signerVersion(secret, proposals[1]) == 1,
                  "createMeta signs from the v1 ContinuID head");
            check(successorVersion(secret, proposals[1]) == 2, "createMeta's new ContinuID head is v2");
        }
    } catch (const std::exception& e) {
        check(false, "client at version 2 with a v1 identity", std::string("threw: ") + e.what());
    }

    try {
        std::cout << "\nA client at OTS version 2 creates a v2 token remainder\n";
        knishio_test::StubValidator stub;
        auto client = clientAt(stub.uri(), 2);
        (void)client->requestAuthToken(secret).get();   // no ContinuID: fresh AUTH wallet
        const std::string tokenPosition(64, 'd');
        const std::string tokenAddressV1 =
            Wallet::generateWalletAddress(Wallet::generateWalletKey(secret, "OTSV2", tokenPosition, 1));
        stub.setBalance({{"position", tokenPosition}, {"address", tokenAddressV1}, {"tokenSlug", "OTSV2"},
                         {"amount", "100"}, {"pubkey", nullptr}, {"batchId", nullptr}, {"bundleHash", bundle},
                         {"tokenUnits", json::array()}});
        const std::string other = Wallet::generateBundleHash(knishio::KnishIOClient::generateSecret());
        (void)client->transferToken(other, "OTSV2", 10).get();
        const auto proposals = stub.requests("ProposeMolecule");
        check(proposals.size() == 2, "two molecules proposed", "got " + std::to_string(proposals.size()));
        if (proposals.size() == 2) {
            const json& atoms = proposals[1]["variables"]["molecule"]["atoms"];
            check(atomString(atoms[0], "walletAddress") == tokenAddressV1 && signerVersion(secret, proposals[1]) == 1,
                  "the transfer signs from the v1 balance wallet");
            int remainderVersion = -1;
            for (const auto& atom : atoms) {
                if (atomString(atom, "isotope") == "V" && atomString(atom, "walletAddress") != tokenAddressV1
                    && !atomString(atom, "position").empty()) {
                    remainderVersion = versionOf(secret, "OTSV2", atomString(atom, "position"),
                                                 atomString(atom, "walletAddress"));
                }
            }
            check(remainderVersion == 2, "the token remainder is v2", "got " + std::to_string(remainderVersion));
        }
    } catch (const std::exception& e) {
        check(false, "token remainder at version 2", std::string("threw: ") + e.what());
    }

    try {
        std::cout << "\nA ledger wallet neither version derives" << std::endl;
        knishio_test::StubValidator stub;
        stub.setContinuId(continuIdAt(bundle, position, unrelated));
        auto client = clientAt(stub.uri(), 1);
        (void)client->requestAuthToken(secret).get();   // the pointer falls back to an AUTH wallet
        try {
            (void)knishio::KnishIOClientTestAccess::bind(*client, "USER", position, unrelated);
            check(false, "binding it throws WalletException", "returned a version");
        } catch (const knishio::WalletException& e) {
            check(endsWith(e.what(), notDerived), "binding it throws WalletException", e.what());
        }
        try {
            (void)client->createMeta("OtsV2", "refused", {{"k", "v"}}).get();
            check(false, "createMeta refuses a ContinuID head it cannot derive", "proposed a molecule");
        } catch (const knishio::WalletException& e) {
            check(endsWith(e.what(), notDerived), "createMeta refuses a ContinuID head it cannot derive", e.what());
        }
        const auto proposals = stub.requests("ProposeMolecule");
        check(proposals.size() == 1, "only the login was proposed", "got " + std::to_string(proposals.size()));
        if (!proposals.empty()) {
            const json& login = proposals[0]["variables"]["molecule"]["atoms"][0];
            check(atomString(login, "token") == "AUTH" && signerVersion(secret, proposals[0]) == 1,
                  "the login falls back to a v1 AUTH wallet");
        }
    } catch (const std::exception& e) {
        check(false, "underivable ledger wallet", std::string("threw: ") + e.what());
    }

    return failures == 0 ? 0 : 1;
}

std::string vectorsPath() {
    if (const char* env = std::getenv("KNISHIO_OTS_V2_VECTORS")) {
        return env;
    }
#ifdef KNISHIO_OTS_V2_VECTORS_PATH
    return KNISHIO_OTS_V2_VECTORS_PATH;
#else
    return "../shared-test-results/ots-v2-vectors.json";
#endif
}

const json& findByName(const json& tests, const std::string& name) {
    for (const auto& t : tests) {
        if (t.at("name").get<std::string>() == name) {
            return t;
        }
    }
    throw std::runtime_error("vector not found: " + name);
}

int runVectors() {
    const std::string path = vectorsPath();
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "SKIP: ots-v2-vectors.json not found (standalone checkout)" << std::endl;
        return 77;
    }
    const json vectors = json::parse(file).at("vectors");
    const json& keyTests = vectors.at("key_derivation").at("tests");

    std::cout << "OTS v2 key derivation and address" << std::endl;
    for (const auto& v : keyTests) {
        const auto name = v.at("name").get<std::string>();
        try {
            const auto secret = v.at("secret").get<std::string>();
            const auto token = v.at("token").get<std::string>();
            const auto position = v.at("position").get<std::string>();
            const auto keyV1 = Wallet::generateWalletKey(secret, token, position);
            const auto keyV2 = Wallet::generateWalletKey(secret, token, position, 2);
            check(keyV1 == v.at("expectedKeyV1").get<std::string>(), name + ": v1 key");
            check(keyV2 == v.at("expectedKeyV2").get<std::string>(), name + ": v2 key");
            check(Wallet::generateWalletAddress(v.at("expectedKeyV1").get<std::string>()) ==
                      v.at("expectedAddressV1").get<std::string>(), name + ": v1 address");
            check(Wallet::generateWalletAddress(v.at("expectedKeyV2").get<std::string>()) ==
                      v.at("expectedAddressV2").get<std::string>(), name + ": v2 address");
            check(Wallet(secret, token, position, 64, 1024, 2).address == v.at("expectedAddressV2").get<std::string>(),
                  name + ": v2 wallet address");
        } catch (const std::exception& e) {
            check(false, name, std::string("threw: ") + e.what());
        }
    }
    try {
        (void)Wallet::generateWalletKey("abcdef", "USER", "abcdef", 3);
        check(false, "generateWalletKey refuses OTS version 3", "returned a key");
    } catch (const std::invalid_argument& e) {
        check(std::string(e.what()) == "KnishIO: unsupported OTS version 3; expected 1 or 2.",
              "generateWalletKey refuses OTS version 3", e.what());
    }

    std::cout << "\nOTS v2 normalized hash" << std::endl;
    for (const auto& v : vectors.at("signature").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        const auto normalized = Molecule::normalize(Molecule::enumerate(v.at("molecularHash").get<std::string>()));
        std::vector<int> got(normalized.begin(), normalized.end());
        check(got == v.at("expectedNormalized").get<std::vector<int>>(), name + ": normalize(enumerate(hash))");
    }

    std::cout << "\nOTS v2 wallet ML-KEM identities" << std::endl;
    for (const auto& v : vectors.at("mlkem_identity").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        try {
            const json& k = findByName(keyTests, v.at("keyFrom").get<std::string>());
            const auto secret = k.at("secret").get<std::string>();
            const auto token = k.at("token").get<std::string>();
            const auto position = k.at("position").get<std::string>();
            check(toBase64(Wallet(secret, token, position, 64, 1024, 2).mlkem_public_key) ==
                      v.at("expectedMlKem1024Pubkey").get<std::string>(), name + ": ML-KEM-1024 public key");
            check(toBase64(Wallet(secret, token, position, 64, 768, 2).mlkem_public_key) ==
                      v.at("expectedMlKem768Pubkey").get<std::string>(), name + ": ML-KEM-768 public key");
        } catch (const std::exception& e) {
            check(false, name, std::string("threw: ") + e.what());
        }
    }

    std::cout << "\nOTS v2 molecule verdicts" << std::endl;
    const json& moleculeTests = vectors.at("molecules").at("tests");
    for (const auto& v : moleculeTests) {
        const auto name = v.at("name").get<std::string>();
        const auto expected = v.at("expected").get<std::string>();
        const std::string got = outcome([&] { Molecule::check(Molecule::jsonToObject(v.at("molecule").dump())); });
        check(got == (expected == "verified" ? "ok" : expected), name + " -> " + expected, "got " + got);
    }

    const json& user = findByName(keyTests, "hex_secret_user");
    for (const std::string name : {"genuine_v2", "genuine_v1_control"}) {
        try {
            const json& v = findByName(moleculeTests, name);
            const auto secret = user.at("secret").get<std::string>();
            Molecule molecule = Molecule::jsonToObject(v.at("molecule").dump());
            molecule.sourceWallet = std::make_shared<Wallet>(
                secret, "USER", user.at("position").get<std::string>(), 64, 1024, v.at("otsVersion").get<int>());
            molecule.sign(secret);
            const auto& atoms = v.at("molecule").at("atoms");
            bool same = atoms.size() == molecule.atoms.size();
            for (size_t i = 0; same && i < atoms.size(); i++) {
                same = molecule.atoms[i].otsFragment == atoms[i].at("otsFragment").get<std::string>();
            }
            check(same, "re-signing " + name + " reproduces every otsFragment");
        } catch (const std::exception& e) {
            check(false, "re-signing " + name, std::string("threw: ") + e.what());
        }
    }

    std::cout << "\nOTS malformed declared hash" << std::endl;
    for (const auto& v : vectors.at("malformed_hash").at("tests")) {
        const auto name = v.at("name").get<std::string>();
        const auto expected = v.at("expected").get<std::string>();
        const std::string got = outcome([&] { Molecule::verifyOts(Molecule::jsonToObject(v.at("molecule").dump())); });
        check(got == expected, name + " -> " + expected, "got " + got);
    }

    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string mode = argc > 1 ? argv[1] : "roundtrip";
    int rc = 0;
    if (mode == "vectors") {
        rc = runVectors();
    } else if (mode == "client") {
        rc = runClient();
    } else if (mode == "address") {
        rc = runAddress();
    } else {
        rc = runRoundTrip();
    }
    if (rc == 77) {
        return rc;
    }
    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
