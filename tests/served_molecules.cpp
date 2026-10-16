// Served-molecule verification and Version4 hash vectors.
//
// Reads tests/fixtures/served-molecules.json (molecules exactly as a validator's GraphQL API
// serves them) and tests/fixtures/version4-hash-vectors.json (client-format atoms, the exact
// view JSON hashed and the expected base17 hash). Both are vendored copies of the masters in
// the monorepo's sdks/shared-test-results/. A missing file exits 77 (CTest: skipped).

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "Atom.h"
#include "Molecule.h"
#include "third_party/nlohmann/json.hpp"

using json = nlohmann::json;
using KnishIO::Atom;
using KnishIO::Molecule;

namespace {

int failures = 0;

void check(bool ok, const std::string& name, const std::string& detail = {}) {
    if (ok) {
        std::cout << "  \033[0;32mPASS\033[0m " << name << std::endl;
    } else {
        ++failures;
        std::cout << "  \033[0;31mFAIL\033[0m " << name << (detail.empty() ? "" : ": " + detail) << std::endl;
    }
}

std::string fixturePath(const char* env, const char* fallback) {
    if (const char* value = std::getenv(env)) {
        return value;
    }
    return fallback;
}

#ifndef KNISHIO_SERVED_MOLECULES_PATH
#define KNISHIO_SERVED_MOLECULES_PATH "fixtures/served-molecules.json"
#endif
#ifndef KNISHIO_VERSION4_VECTORS_PATH
#define KNISHIO_VERSION4_VECTORS_PATH "fixtures/version4-hash-vectors.json"
#endif

bool load(const std::string& path, json& out) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    out = json::parse(file);
    return true;
}

json withVersions(json molecule, const json& version) {
    for (auto& atom : molecule.at("atoms")) {
        atom["version"] = version;
    }
    return molecule;
}

std::string describe(const KnishIO::ServedVerification& r) {
    return std::string("verified=") + (r.verified ? "true" : "false") + " error=" + r.error;
}

void expectVerified(const json& molecule, const std::string& name) {
    const auto r = Molecule::verifyFromServerData(molecule.dump());
    check(r.verified && r.error.empty() && r.molecularHash == molecule.at("molecularHash").get<std::string>(),
          name, describe(r));
}

void expectMismatch(const json& molecule, const std::string& name) {
    const auto r = Molecule::verifyFromServerData(molecule.dump());
    check(!r.verified && r.error == "Molecular hash mismatch", name, describe(r));
}

void servedCases(const json& served) {
    std::cout << "Served molecules" << std::endl;
    expectVerified(served.at("v1"), "1. v1 verifies");
    expectVerified(served.at("v2"), "1. v2 verifies");
    expectVerified(served.at("v2ts"), "2. v2ts verifies through the \"4\" retry");
    expectVerified(withVersions(served.at("v2ts"), "4"), "3. v2ts with version \"4\" on every atom verifies");
    expectVerified(served.at("v3rust"), "4. v3rust (served with \"3\") verifies");
    expectVerified(withVersions(served.at("v3rust"), nullptr), "5. v3rust without versions verifies through the \"3\" retry");

    json tampered = served.at("v3rust");
    tampered["atoms"][0]["metaId"] = "rust-pre-tampered";
    expectMismatch(tampered, "6. tampered v3rust fails with versions");
    expectMismatch(withVersions(tampered, nullptr), "6. tampered v3rust fails without versions");

    expectMismatch(withVersions(served.at("v1"), "4"), "7. v1 with version \"4\" fails (a served version disables the retry)");

    for (const std::string& bad : {std::string("[]"), std::string("{}"), std::string("not json"),
                                   std::string(R"({"atoms":"x"})")}) {
        const auto r = Molecule::verifyFromServerData(bad);
        check(!r.verified && !r.error.empty(), "malformed input " + bad + " is not verified", describe(r));
    }
}

void createdAtCases() {
    std::cout << "\ncreatedAt normalization" << std::endl;
    check(Molecule::toSignedTimestamp(std::string("2026-10-14T20:02:37+00:00")) == std::optional<std::string>("1792008157000"),
          "8. RFC 3339 with offset");
    check(Molecule::toSignedTimestamp(std::string("2026-10-14T20:02:37.110Z")) == std::optional<std::string>("1792008157110"),
          "8. RFC 3339 with fraction and Z");
    check(Molecule::toSignedTimestamp(1792008157110LL) == "1792008157110", "8. integer");
    check(Molecule::toSignedTimestamp(std::string("1792008157110")) == std::optional<std::string>("1792008157110"),
          "8. digit string unchanged");
    check(Molecule::toSignedTimestamp(std::string("not-a-date")) == std::optional<std::string>("not-a-date"),
          "8. other strings unchanged");
    check(Molecule::toSignedTimestamp(std::string("2026-10-14T22:02:37.1109+02:00")) == std::optional<std::string>("1792008157110"),
          "8. offset applied, fraction truncated to 3 digits");
    check(!Molecule::toSignedTimestamp(std::string("")).has_value(), "8. empty string is absent");
}

void vectorCases(const json& vectors) {
    std::cout << "\nVersion4 hash vectors" << std::endl;
    const std::vector<std::string> expectedNames = {"v4-basic", "v3-basic", "slash-unicode", "control-quote",
                                                    "line-separators", "nulls", "empty-strings", "empty-version",
                                                    "index-order"};
    std::vector<std::string> names;
    for (const auto& c : vectors.at("cases")) {
        names.push_back(c.at("name").get<std::string>());
    }
    check(names == expectedNames, "9. the vectors file has exactly the 9 expected cases");
    for (const auto& c : vectors.at("cases")) {
        const auto name = c.at("name").get<std::string>();
        try {
            std::vector<Atom> atoms;
            for (const auto& a : c.at("atoms")) {
                atoms.push_back(Atom::jsonToObject(a.dump()));
            }
            const auto view = Atom::version4ViewJson(atoms);
            check(view == c.at("viewJson").get<std::string>(), "9. " + name + ": view JSON", view);
            const auto hash = Atom::hashAtomsBase17(atoms);
            check(hash == c.at("expectedHash").get<std::string>(), "9. " + name + ": hash", hash);
        } catch (const std::exception& e) {
            check(false, "9. " + name, std::string("threw: ") + e.what());
        }
    }

    std::cout << "\nLegacy (unversioned) hash vectors" << std::endl;
    std::vector<std::string> legacyNames;
    for (const auto& c : vectors.at("legacyCases")) {
        legacyNames.push_back(c.at("name").get<std::string>());
    }
    check(legacyNames == std::vector<std::string>{"legacy-empty-strings", "legacy-nulls"},
          "9. the vectors file has exactly the 2 expected legacy cases");
    for (const auto& c : vectors.at("legacyCases")) {
        const auto name = c.at("name").get<std::string>();
        try {
            std::vector<Atom> atoms;
            for (const auto& a : c.at("atoms")) {
                atoms.push_back(Atom::jsonToObject(a.dump()));
            }
            const auto hash = Atom::hashAtomsBase17(atoms);
            check(hash == c.at("expectedHash").get<std::string>(), "9. " + name + ": legacy hash", hash);
        } catch (const std::exception& e) {
            check(false, "9. " + name, std::string("threw: ") + e.what());
        }
    }
}

}  // namespace

int main() {
    json served;
    json vectors;
    if (!load(fixturePath("KNISHIO_SERVED_MOLECULES", KNISHIO_SERVED_MOLECULES_PATH), served)
        || !load(fixturePath("KNISHIO_VERSION4_VECTORS", KNISHIO_VERSION4_VECTORS_PATH), vectors)) {
        std::cout << "SKIP: served-molecules.json or version4-hash-vectors.json not found" << std::endl;
        return 77;
    }
    servedCases(served);
    createdAtCases();
    vectorCases(vectors);

    std::cout << std::endl;
    if (failures > 0) {
        std::cout << "\033[0;31m" << failures << " assertion(s) failed\033[0m" << std::endl;
        return 1;
    }
    std::cout << "\033[0;32mAll assertions passed\033[0m" << std::endl;
    return 0;
}
