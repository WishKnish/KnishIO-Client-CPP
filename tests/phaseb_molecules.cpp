/**
 * @file phaseb_molecules.cpp
 * @brief Replenish, stackable fusion, buffer withdraw, createToken units and the pre-submit check.
 *
 * Two halves:
 *  - the shared canonical vectors token_replenish, stackable_fusion_conservation and
 *    buffer_withdraw_fresh_remainder, built with the SDK's own Molecule builders and checked with
 *    Molecule::check (the single-unit fusion must throw);
 *  - the client operations against a loopback validator stub (tests/loopback_validator.h; the
 *    client has no transport seam): the create_token_units vectors through createToken (tokenUnits
 *    as compact [id, name, metas] triples), which wallet replenishToken credits and which pointer
 *    signs it, how fuseToken assigns batch ids and recipients, that withdrawBufferToken reads
 *    Balance(type: "buffer") and remainders at a fresh position, that a built molecule failing the
 *    check is never sent, and that the raw proposeMolecule path sends a caller-built molecule
 *    unchecked.
 */
#include <algorithm>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "AtomsNotFoundException.h"
#include "KnishIOClient.h"
#include "Molecule.h"
#include "Wallet.h"
#include "loopback_validator.h"
#include "response/Response.h"
#include "third_party/nlohmann/json.hpp"

using knishio_test::Session;
using nlohmann::json;

namespace knishio {
// Declared a friend of KnishIOClient: reaches the submit pipeline every client operation uses.
class KnishIOClientTestAccess {
public:
    static std::unique_ptr<response::ResponseProposeMolecule> submitBuilt(KnishIOClient& client, KnishIO::Molecule& mol) {
        return client.submitMolecule(mol);
    }
};
}  // namespace knishio

namespace {

int failures = 0;
const std::string ZERO_BUNDLE(64, '0');

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

std::optional<std::string> metaOf(const std::vector<std::pair<std::string, std::string>>& meta, const std::string& key) {
    for (const auto& kv : meta) {
        if (kv.first == key) return kv.second;
    }
    return std::nullopt;
}

std::vector<std::string> metaKeys(const std::vector<std::pair<std::string, std::string>>& meta) {
    std::vector<std::string> keys;
    for (const auto& kv : meta) keys.push_back(kv.first);
    return keys;
}

// Unit ids of a tokenUnits meta ([] when absent: JS omits an empty list).
std::vector<std::string> unitIds(const std::vector<std::pair<std::string, std::string>>& meta) {
    std::vector<std::string> ids;
    if (auto raw = metaOf(meta, "tokenUnits")) {
        for (const auto& unit : json::parse(*raw)) ids.push_back(unit.at(0).get<std::string>());
    }
    return ids;
}

std::vector<KnishIO::TokenUnit> triples(const std::vector<std::string>& ids) {
    std::vector<KnishIO::TokenUnit> units;
    for (const auto& id : ids) units.push_back({id, id, {}});
    return units;
}

std::string join(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) out += (out.empty() ? "" : ",") + s;
    return "[" + out + "]";
}

// ------------------------------------------------------------------------------------------
// Vectors
// ------------------------------------------------------------------------------------------

void replenishVectors(const json& vectors, const std::string& secret) {
    std::cout << "\ntoken_replenish vectors\n";
    for (const auto& tv : vectors.at("token_replenish").at("tests")) {
        const std::string name = tv.at("name").get<std::string>();
        const std::string token = tv.at("token").get<std::string>();
        std::vector<KnishIO::TokenUnit> units;
        for (const auto& u : tv.at("units")) units.push_back({u.at(0).get<std::string>(), u.at(1).get<std::string>(), {}});
        const std::string amount = tv.at("amount").is_null() ? "0" : std::to_string(tv.at("amount").get<long long>());

        KnishIO::Wallet source(secret, "USER");
        KnishIO::Wallet credited(secret, token);
        KnishIO::Wallet remainder(secret, "USER");
        KnishIO::Molecule mol;
        mol.sourceWallet = std::make_shared<KnishIO::Wallet>(source);
        mol.remainderWallet = std::make_shared<KnishIO::Wallet>(remainder);
        mol.initTokenReplenish(source, credited, amount, units);
        mol.sign(secret);

        std::vector<std::string> isotopes;
        for (const auto& a : mol.atoms) isotopes.push_back(a.isotope);
        const auto& c = mol.atoms.at(0);
        const bool shape = isotopes == tv.at("expectedIsotopes").get<std::vector<std::string>>()
            && c.value == tv.at("expectedCValue").get<std::string>()
            && c.metaType == tv.at("expectedMetaType").get<std::string>()
            && c.metaId == tv.at("expectedMetaId").get<std::string>()
            && metaOf(c.meta, "action") == tv.at("expectedAction").get<std::string>();
        check(shape, name + ": isotopes, C value, metaType/metaId, action", join(isotopes) + " value " + c.value);

        const bool unitsOk = tv.at("expectedTokenUnitIds").is_null()
            ? !metaOf(c.meta, "tokenUnits").has_value()
            : unitIds(c.meta) == tv.at("expectedTokenUnitIds").get<std::vector<std::string>>();
        check(unitsOk, name + ": tokenUnits ids", join(unitIds(c.meta)));

        std::vector<std::string> expectedKeys = {"action", "address", "position", "pubkey"};
        if (!units.empty()) expectedKeys.push_back("tokenUnits");
        check(metaKeys(c.meta) == expectedKeys, name + ": C metas are " + join(expectedKeys), join(metaKeys(c.meta)));
        check(metaOf(c.meta, "address") == credited.address && metaOf(c.meta, "position") == credited.position,
              name + ": address/position name the credited wallet");
        check(c.position == source.position && c.token == "USER", name + ": C atom is signed by the USER source");

        bool checked = true;
        std::string why;
        try { KnishIO::Molecule::check(mol); } catch (const std::exception& e) { checked = false; why = e.what(); }
        check(checked, name + ": Molecule::check passes", why);
    }
}

void fusionVectors(const json& vectors, const std::string& secret) {
    std::cout << "\nstackable_fusion_conservation vectors\n";
    const std::string token = "FUSETOK";
    for (const auto& tv : vectors.at("stackable_fusion_conservation").at("tests")) {
        const std::string name = tv.at("name").get<std::string>();
        const auto sourceIds = tv.at("sourceUnits").get<std::vector<std::string>>();
        const auto fuse = tv.at("fuse").get<std::vector<std::string>>();
        const std::string newId = tv.at("newUnitId").get<std::string>();

        KnishIO::Wallet source(secret, token);
        source.balance = std::to_string(sourceIds.size());
        source.tokenUnits = triples(sourceIds);
        KnishIO::Wallet recipient(secret, token);
        KnishIO::Wallet remainder(secret, token);
        KnishIO::Molecule mol;
        mol.sourceWallet = std::make_shared<KnishIO::Wallet>(source);
        mol.remainderWallet = std::make_shared<KnishIO::Wallet>(remainder);

        if (tv.value("mustReject", false)) {
            std::string error;
            try {
                mol.initTokenFusion(source, recipient, remainder, fuse, newId);
            } catch (const std::exception& e) {
                error = e.what();
            }
            check(error.find(tv.at("expectedErrorContains").get<std::string>()) != std::string::npos,
                  name + ": rejected with '" + tv.at("expectedErrorContains").get<std::string>() + "'", error);
            continue;
        }

        mol.initTokenFusion(source, recipient, remainder, fuse, newId);
        mol.sign(secret);
        const auto& atoms = mol.atoms;

        std::vector<std::string> isotopes;
        long long sum = 0;
        for (const auto& a : atoms) {
            isotopes.push_back(a.isotope);
            sum += std::stoll(a.value);
        }
        check(isotopes == tv.at("expectedIsotopes").get<std::vector<std::string>>(), name + ": isotopes", join(isotopes));
        check(atoms.size() == 4
                  && atoms[0].value == tv.at("expectedSourceValue").get<std::string>()
                  && atoms[1].value == tv.at("expectedBurnValue").get<std::string>()
                  && atoms[2].value == tv.at("expectedFusionValue").get<std::string>()
                  && atoms[3].value == tv.at("expectedRemainderValue").get<std::string>(),
              name + ": values");
        check(std::to_string(sum) == tv.at("expectedSum").get<std::string>(), name + ": V+F sum " + std::to_string(sum));
        check(unitIds(atoms[0].meta) == tv.at("expectedSourceUnitIds").get<std::vector<std::string>>(),
              name + ": source tokenUnits = fused units in source order", join(unitIds(atoms[0].meta)));
        check(unitIds(atoms[1].meta) == tv.at("expectedBurnUnitIds").get<std::vector<std::string>>(),
              name + ": burn tokenUnits", join(unitIds(atoms[1].meta)));
        check(unitIds(atoms[3].meta) == tv.at("expectedRemainderUnitIds").get<std::vector<std::string>>(),
              name + ": remainder tokenUnits", join(unitIds(atoms[3].meta)));
        check(atoms[1].metaType == "walletBundle" && atoms[1].metaId == ZERO_BUNDLE
                  && atoms[2].metaType == "walletBundle" && atoms[2].metaId == recipient.bundle
                  && atoms[3].metaType == "walletBundle" && atoms[3].metaId == source.bundle,
              name + ": metaType/metaId of burn, F and remainder");

        const json fUnits = json::parse(metaOf(atoms[2].meta, "tokenUnits").value_or("[]"));
        std::vector<std::string> fusedIds;
        if (fUnits.size() == 1) {
            for (const auto& f : fUnits[0].at(2).at("fusedTokenUnits")) fusedIds.push_back(f.at(0).get<std::string>());
        }
        check(fUnits.size() == 1 && fUnits[0].at(0) == newId && fUnits[0].at(1) == newId
                  && fusedIds == tv.at("expectedFusedTokenUnitIds").get<std::vector<std::string>>(),
              name + ": F tokenUnits = [N], N.metas.fusedTokenUnits ids", fUnits.dump());
        check(std::none_of(atoms.begin(), atoms.end(), [](const KnishIO::Atom& a) { return !a.batchId.empty(); }),
              name + ": no batch fields for a source without a batch id");

        bool checked = true;
        std::string why;
        try { KnishIO::Molecule::check(mol); } catch (const std::exception& e) { checked = false; why = e.what(); }
        check(checked, name + ": Molecule::check passes", why);
    }
}

void withdrawVectors(const json& vectors, const std::string& secret) {
    std::cout << "\nbuffer_withdraw_fresh_remainder vectors\n";
    const std::string token = "BUFTOK";
    for (const auto& tv : vectors.at("buffer_withdraw_fresh_remainder").at("tests")) {
        const std::string name = tv.at("name").get<std::string>();
        KnishIO::Wallet source(secret, token);
        source.balance = std::to_string(tv.at("sourceBalance").get<long long>());
        KnishIO::Wallet recipient(secret, token);
        recipient.address = "";
        recipient.position = "";
        KnishIO::Wallet remainder(secret, token);

        KnishIO::Molecule mol;
        mol.sourceWallet = std::make_shared<KnishIO::Wallet>(source);
        mol.remainderWallet = std::make_shared<KnishIO::Wallet>(remainder);
        mol.initWithdrawBuffer(source, {recipient}, {std::to_string(tv.at("amount").get<long long>())}, remainder);
        mol.sign(secret);
        const auto& atoms = mol.atoms;

        std::vector<std::string> isotopes;
        long long sum = 0;
        for (const auto& a : atoms) {
            isotopes.push_back(a.isotope);
            sum += std::stoll(a.value);
        }
        check(isotopes == tv.at("expectedIsotopes").get<std::vector<std::string>>()
                  && atoms[0].value == tv.at("expectedSourceValue").get<std::string>()
                  && atoms[1].value == tv.at("expectedRecipientValue").get<std::string>()
                  && atoms[2].value == tv.at("expectedRemainderValue").get<std::string>()
                  && std::to_string(sum) == tv.at("expectedSum").get<std::string>(),
              name + ": isotopes, values, sum", join(isotopes));
        check((atoms[2].position != atoms[0].position) == tv.at("expectedRemainderPositionDistinctFromSource").get<bool>(),
              name + ": remainder position distinct from the source");
        bool checked = true;
        std::string why;
        try { KnishIO::Molecule::check(mol); } catch (const std::exception& e) { checked = false; why = e.what(); }
        check(checked, name + ": Molecule::check passes", why);
    }
}

const json& atomsOf(const json& proposal) { return proposal["variables"]["molecule"]["atoms"]; }

std::optional<std::string> jmeta(const json& atom, const std::string& key) {
    for (const auto& kv : atom["meta"]) {
        if (kv.value("key", "") == key && kv["value"].is_string()) return kv["value"].get<std::string>();
    }
    return std::nullopt;
}

std::vector<std::string> jkeys(const json& atom) {
    std::vector<std::string> keys;
    for (const auto& kv : atom["meta"]) keys.push_back(kv.value("key", ""));
    return keys;
}

std::string jstr(const json& atom, const std::string& key) {
    return atom.contains(key) && atom[key].is_string() ? atom[key].get<std::string>() : "";
}

std::string randomPosition() { return knishio::KnishIOClient::generateSecret(64); }

template <typename F>
std::string errorOf(F&& op) {
    try {
        op();
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

// ------------------------------------------------------------------------------------------
// Client operations
// ------------------------------------------------------------------------------------------

// create_token_units: the public createToken with bare unit ids sends the C atom meta tokenUnits
// as compact [id, id, {}] triples, byte-exact.
void createTokenUnitsVectors(const json& vectors) {
    std::cout << "\ncreate_token_units vectors: createToken with stackable units\n";
    for (const auto& tv : vectors.at("create_token_units").at("tests")) {
        const std::string name = tv.at("name").get<std::string>();
        const std::string token = tv.at("token").get<std::string>();
        Session s;
        auto resp = s.client->createToken(token, 0, {{"fungibility", "stackable"}},
                                          tv.at("units").get<std::vector<std::string>>()).get();
        const auto sent = s.built();
        // submitMolecule runs Molecule::check first and sends nothing when it throws.
        check(sent.size() == 1, name + ": one molecule proposed (Molecule::check passed)", std::to_string(sent.size()));
        if (sent.size() != 1) continue;
        const auto& a = atomsOf(sent[0]);
        std::vector<std::string> isotopes;
        for (const auto& atom : a) isotopes.push_back(jstr(atom, "isotope"));
        check(isotopes == std::vector<std::string>{"C", "I"}, name + ": atoms C, I", join(isotopes));
        const json& c = a.at(0);
        check(jstr(c, "value") == tv.at("expectedCValue").get<std::string>()
                  && jstr(c, "metaType") == tv.at("expectedMetaType").get<std::string>()
                  && jstr(c, "metaId") == tv.at("expectedMetaId").get<std::string>(),
              name + ": C value, metaType, metaId",
              jstr(c, "value") + " " + jstr(c, "metaType") + " " + jstr(c, "metaId"));
        const std::string tokenUnits = jmeta(c, "tokenUnits").value_or("<none>");
        std::cout << "    tokenUnits " << tokenUnits << std::endl;
        check(tokenUnits == tv.at("expectedTokenUnits").get<std::string>(), name + ": tokenUnits byte-exact",
              "got " + tokenUnits + ", expected " + tv.at("expectedTokenUnits").get<std::string>());
        std::vector<std::string> ids;
        const json parsed = json::parse(tokenUnits, nullptr, false);
        if (parsed.is_array()) {
            for (const auto& u : parsed) ids.push_back(u.is_array() ? u.at(0).get<std::string>() : u.dump());
        }
        check(ids == tv.at("expectedTokenUnitIds").get<std::vector<std::string>>(), name + ": tokenUnits ids", join(ids));
    }
}

void replenishCreditsExistingWallet() {
    std::cout << "\nreplenishToken: existing wallet, signed from the ContinuID pointer\n";
    Session s;
    const std::string pointer = randomPosition();
    const std::string walletPos = randomPosition();
    s.pointAt(pointer);
    s.stub.setBalance(s.balanceRow("REPL", walletPos, "1000", "batch-existing"));

    auto resp = s.client->replenishToken("REPL", 500).get();
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& atoms = atomsOf(sent[0]);
    const KnishIO::Wallet credited(s.secret, "REPL", walletPos);
    check(atoms.size() == 2 && jstr(atoms[0], "isotope") == "C" && jstr(atoms[1], "isotope") == "I", "atoms C, I");
    check(jstr(atoms[0], "position") == pointer && jstr(atoms[0], "token") == "USER", "C signed by USER at the pointer");
    check(jstr(atoms[0], "value") == "500" && jstr(atoms[0], "metaType") == "token" && jstr(atoms[0], "metaId") == "REPL",
          "C value 500, metaType token, metaId REPL");
    check(jkeys(atoms[0]) == std::vector<std::string>{"action", "address", "position", "pubkey", "batchId"},
          "metas action, address, position, pubkey, batchId", join(jkeys(atoms[0])));
    check(jmeta(atoms[0], "address") == credited.address && jmeta(atoms[0], "position") == walletPos
              && jmeta(atoms[0], "batchId") == "batch-existing" && jstr(atoms[0], "batchId") == "batch-existing",
          "credits the existing wallet; atom and meta carry its batch id");
    check(jstr(atoms[1], "position") != pointer && jmeta(atoms[1], "previousPosition") == pointer,
          "I atom: fresh remainder, previousPosition = pointer");
}

void replenishCreatesWalletForStackableUnits() {
    std::cout << "\nreplenishToken: no wallet yet, stackable units\n";
    Session s;
    s.pointAt(randomPosition());
    s.stub.setBalance(nullptr);

    auto resp = s.client->replenishToken("RSTK", 0, {"R1", "R2"}).get();
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& c = atomsOf(sent[0])[0];
    check(jstr(c, "value") == "2", "C value = unit count", jstr(c, "value"));
    check(jkeys(c) == std::vector<std::string>{"action", "address", "position", "pubkey", "tokenUnits"},
          "metas action, address, position, pubkey, tokenUnits", join(jkeys(c)));
    check(jmeta(c, "tokenUnits") == R"([["R1","R1",{}],["R2","R2",{}]])", "tokenUnits compact triples",
          jmeta(c, "tokenUnits").value_or("<none>"));
    const auto position = jmeta(c, "position").value_or("");
    check(position.size() == 64 && jmeta(c, "address") == KnishIO::Wallet(s.secret, "RSTK", position).address,
          "credits a new wallet of the identity");
}

void replenishRejectsNonPositiveAmount() {
    std::cout << "\nreplenishToken: amount checks send nothing\n";
    Session s;
    s.pointAt(randomPosition());
    const std::string zero = errorOf([&] { (void)s.client->replenishToken("REPL", 0).get(); });
    check(zero.find("must be positive") != std::string::npos, "amount 0 refused", zero);
    const std::string mismatch = errorOf([&] { (void)s.client->replenishToken("REPL", 3, {"R1", "R2"}).get(); });
    check(mismatch.find("unit count") != std::string::npos, "amount != unit count refused", mismatch);
    check(s.built().empty(), "no molecule proposed");
}

void fuseOwnBundleWithBatchedSource() {
    std::cout << "\nfuseToken: own bundle, source with a batch id\n";
    Session s;
    const std::string sourcePos = randomPosition();
    s.stub.setBalance(s.balanceRow("STK", sourcePos, "5", "batch-src", {"U1", "U2", "U3", "U4", "U5"}));

    auto resp = s.client->fuseToken(s.bundle, "STK", "FUSED", {"U2", "U4", "U5"}).get();
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& a = atomsOf(sent[0]);
    std::vector<std::string> isotopes;
    for (const auto& atom : a) isotopes.push_back(jstr(atom, "isotope"));
    check(isotopes == std::vector<std::string>{"V", "V", "F", "V"}, "atoms V, V, F, V", join(isotopes));
    if (a.size() != 4) return;
    check(jstr(a[0], "position") == sourcePos && jstr(a[0], "value") == "-5", "source signs at its position, -5");
    check(jmeta(a[0], "tokenUnits") == R"([["U2","U2",{}],["U4","U4",{}],["U5","U5",{}]])", "source carries the fused units",
          jmeta(a[0], "tokenUnits").value_or("<none>"));
    check(jmeta(a[2], "tokenUnits")
              == R"([["FUSED","FUSED",{"fusedTokenUnits":[["U2","U2",{}],["U4","U4",{}],["U5","U5",{}]]}]])",
          "F carries N with fusedTokenUnits", jmeta(a[2], "tokenUnits").value_or("<none>"));
    check(jstr(a[2], "metaId") == s.bundle && jstr(a[2], "walletAddress").size() == 64
              && jstr(a[2], "walletAddress") == KnishIO::Wallet(s.secret, "STK", jstr(a[2], "position")).address,
          "F recipient is a fresh wallet of the own bundle");
    check(jstr(a[0], "batchId") == "batch-src" && jstr(a[3], "batchId") == "batch-src", "source and remainder keep the batch id");
    const std::string burnBatch = jstr(a[1], "batchId");
    const std::string fBatch = jstr(a[2], "batchId");
    check(burnBatch.size() == 64 && fBatch.size() == 64 && burnBatch != fBatch && burnBatch != "batch-src" && fBatch != "batch-src",
          "burn and F each get a fresh batch id", burnBatch + " / " + fBatch);
    check(jstr(a[3], "position") != sourcePos && jmeta(a[3], "tokenUnits") == R"([["U1","U1",{}],["U3","U3",{}]])",
          "remainder: fresh position, kept units");
}

void fuseForeignBundle() {
    std::cout << "\nfuseToken: another bundle, source without a batch id, B = M\n";
    Session s;
    const std::string other = KnishIO::Wallet::generateBundleHash(knishio::KnishIOClient::generateSecret());
    s.stub.setBalance(s.balanceRow("STK", randomPosition(), "2", "", {"V1", "V2"}));

    auto resp = s.client->fuseToken(other, "STK", "FUSED2", {"V1", "V2"}).get();
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& a = atomsOf(sent[0]);
    check(a.size() == 4 && jstr(a[2], "metaId") == other && jstr(a[2], "walletAddress").empty()
              && jstr(a[2], "position").empty(),
          "F recipient is the addressless wallet of the other bundle");
    check(a.size() == 4 && jstr(a[3], "value") == "0" && !jmeta(a[3], "tokenUnits").has_value(),
          "B = M: remainder value 0, tokenUnits omitted");
    check(std::all_of(a.begin(), a.end(), [](const json& atom) { return atom["batchId"].is_null(); }),
          "no batch fields for a source without a batch id");
}

void fuseRefusedLocally() {
    std::cout << "\nfuseToken: client checks send nothing\n";
    Session s;
    s.stub.setBalance(s.balanceRow("STK", randomPosition(), "3", "", {"U1", "U2", "U3"}));
    const std::string single = errorOf([&] { (void)s.client->fuseToken(s.bundle, "STK", "N", {"U1"}).get(); });
    check(single.find("Token fusion requires at least two token units") != std::string::npos, "one unit refused", single);
    const std::string missing = errorOf([&] { (void)s.client->fuseToken(s.bundle, "STK", "N", {"U1", "U9"}).get(); });
    check(missing.find("not found in the source wallet") != std::string::npos, "unknown unit refused", missing);
    const std::string exists = errorOf([&] { (void)s.client->fuseToken(s.bundle, "STK", "U3", {"U1", "U2"}).get(); });
    check(exists.find("Token fusion unit id already exists in the source wallet") != std::string::npos,
          "existing new-unit id refused", exists);
    check(s.built().empty(), "no molecule proposed");
}

void withdrawReadsBufferAndRemaindersFresh() {
    std::cout << "\nwithdrawBufferToken: Balance(type: buffer), fresh remainder\n";
    Session s;
    const std::string bufferPos = randomPosition();
    const std::string regularPos = randomPosition();
    s.stub.setBalance(s.balanceRow("BUF", regularPos, "900", ""), s.balanceRow("BUF", bufferPos, "50", ""));

    auto resp = s.client->withdrawBufferToken("BUF", 20).get();
    const auto balances = s.stub.requests("Balance");
    check(!balances.empty() && balances.back()["variables"].value("type", json(nullptr)) == "buffer",
          "the source comes from Balance(type: \"buffer\")");
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& a = atomsOf(sent[0]);
    check(a.size() == 3 && jstr(a[0], "isotope") == "B" && jstr(a[1], "isotope") == "V" && jstr(a[2], "isotope") == "B",
          "atoms B, V, B");
    if (a.size() != 3) return;
    check(jstr(a[0], "position") == bufferPos && jstr(a[0], "value") == "-50", "source is the buffer wallet, -50");
    check(jstr(a[1], "value") == "20" && jstr(a[1], "metaId") == s.bundle && jstr(a[1], "walletAddress").empty()
              && a[1]["batchId"].is_null(),
          "recipient: addressless, own bundle, no batch id");
    check(jstr(a[2], "value") == "30" && jstr(a[2], "position") != bufferPos && jstr(a[2], "position").size() == 64
              && jstr(a[2], "walletAddress") == KnishIO::Wallet(s.secret, "BUF", jstr(a[2], "position")).address,
          "remainder: 30 at a fresh position of the identity");
}

void presubmitCheckRefusesBuiltMolecule() {
    std::cout << "\nPre-submit check: a built USER-signed molecule without its ContinuID atom\n";
    Session s;
    KnishIO::Wallet user(s.secret, "USER");
    KnishIO::Molecule mol("public");
    mol.remainderWallet = std::make_shared<KnishIO::Wallet>(s.secret, "USER");
    mol.initMeta(user, {{"appRole", "admin"}}, "walletBundle", s.bundle);
    mol.atoms.pop_back();   // the defective builder: drops the I atom

    bool atomsMissing = false;
    std::string what;
    try {
        (void)knishio::KnishIOClientTestAccess::submitBuilt(*s.client, mol);
    } catch (const AtomsNotFoundException& e) {
        atomsMissing = true;
        what = e.what();
    } catch (const std::exception& e) {
        what = e.what();
    }
    check(atomsMissing && what.find("ContinuID") != std::string::npos, "refused with AtomsNotFoundException", what);
    check(s.built().empty(), "no molecule proposed");
}

void rawProposeSendsUnchecked() {
    std::cout << "\nRaw proposeMolecule: the same molecule is sent unchanged\n";
    Session s;
    KnishIO::Wallet user(s.secret, "USER");
    auto* mol = new KnishIO::Molecule("public");
    mol->remainderWallet = std::make_shared<KnishIO::Wallet>(s.secret, "USER");
    mol->initMeta(user, {{"appRole", "admin"}}, "walletBundle", s.bundle);
    mol->atoms.pop_back();

    auto resp = s.client->proposeMolecule(mol).get();
    const auto sent = s.built();
    check(sent.size() == 1, "one molecule proposed", std::to_string(sent.size()));
    if (sent.size() != 1) return;
    const auto& a = atomsOf(sent[0]);
    check(a.size() == 1 && jstr(a[0], "isotope") == "M" && jstr(a[0], "position") == user.position,
          "the M-only molecule reached the validator as built");
}

}  // namespace

int main() {
    std::cout << "Phase B molecules: replenish, stackable fusion, buffer withdraw, createToken units, pre-submit check\n";

    std::ifstream f(KNISHIO_VECTORS_PATH);
    if (!f.is_open()) {
        std::cout << "  FAIL canonical-patent-vectors.json not found at " << KNISHIO_VECTORS_PATH << std::endl;
        return 1;
    }
    const json vectors = json::parse(f).at("vectors");
    const std::string secret = knishio::KnishIOClient::generateSecret("phaseb-molecules-test-seed");
    replenishVectors(vectors, secret);
    fusionVectors(vectors, secret);
    withdrawVectors(vectors, secret);

    createTokenUnitsVectors(vectors);
    replenishCreditsExistingWallet();
    replenishCreatesWalletForStackableUnits();
    replenishRejectsNonPositiveAmount();
    fuseOwnBundleWithBatchedSource();
    fuseForeignBundle();
    fuseRefusedLocally();
    withdrawReadsBufferAndRemaindersFresh();
    presubmitCheckRefusesBuiltMolecule();
    rawProposeSendsUnchecked();

    if (failures > 0) {
        std::cout << "\nFailures: " << failures << std::endl;
        return 1;
    }
    std::cout << "\nAll checks passed" << std::endl;
    return 0;
}
