#pragma once

#include <cstdint>  // int8_t in the enumerate/normalize signatures below
#include <memory>
#include <optional>
#include <string>

#include "Atom.h"
#include "TokenUnit.h"

namespace KnishIO {

class Wallet;

// Result of Molecule::verifyFromServerData.
struct ServedVerification {
	std::optional<std::string> molecularHash;
	bool verified = false;
	std::string error;   // empty when verified
};

/**
 * class Molecule
 */
class Molecule
{
public:
	Molecule(const std::string &cellSlug = {});
	~Molecule();

	std::vector<Atom> initValue(const Wallet &sourceWallet, const Wallet &recipientWallet, const Wallet &remainderWallet, const std::string &value);
	// Multi-recipient sibling of initValue: one source debits its FULL balance to fund N recipients
	// (each its own amount + stackable units) plus a remainder back to the sender. recipientWallets
	// is parallel to amounts. Conserves: -balance + Σamounts + (balance-Σ) == 0.
	std::vector<Atom> initValues(const Wallet &sourceWallet, const std::vector<Wallet> &recipientWallets, const std::vector<std::string> &amounts, const Wallet &remainderWallet);
	std::vector<Atom> initTokenCreation(const Wallet &sourceWallet, const Wallet &recipientWallet, const std::string &amount
		, const std::vector<std::pair<std::string, std::string>> &tokenMeta);
	std::vector<Atom> initMeta(const Wallet &wallet, const std::vector<std::pair<std::string, std::string>> &meta, const std::string &metaType, const std::string &metaId);
	std::vector<Atom> initWalletCreation(const Wallet &sourceWallet, const Wallet &wallet, const std::vector<std::pair<std::string, std::string>> &atomMeta = {});
	std::vector<Atom> initShadowWalletClaim(const Wallet &sourceWallet, const Wallet &wallet);
	// Buffer-family (B-isotope) builders, ports of JS Molecule.initDepositBuffer / initWithdrawBuffer.
	// Deposit: V (source -balance) -> B (buffer +amount) -> V (remainder +(balance-amount)). Conserves
	// to 0 across V+B; the B atom carries the balancing weight (so verifyTokenIsotopeV bypasses the
	// V-only sum when a B/F atom is present). tradeRates serialize into the buffer atom meta only when
	// non-empty (JS AtomMeta.setAtomWallet parity); empty -> hash-neutral.
	std::vector<Atom> initDepositBuffer(const Wallet &sourceWallet, const Wallet &bufferWallet, const Wallet &remainderWallet, const std::string &amount, const std::vector<std::pair<std::string, std::string>> &tradeRates = {});
	// Withdraw: B (source -balance) -> N x V (recipient +amount) -> B (remainder +(balance-Σ)).
	// recipientWallets is parallel to amounts; full-balance debit (JS parity) conserves for partial
	// withdraws too: -balance + Σamounts + (balance-Σ) == 0. The remainder MUST be a fresh position
	// (validator 0.6.1 rejects value credited to the consumed signing position). The source B atom
	// carries the source's tokenUnits meta only when it has units.
	std::vector<Atom> initWithdrawBuffer(const Wallet &sourceWallet, const std::vector<Wallet> &recipientWallets, const std::vector<std::string> &amounts, const Wallet &remainderWallet);
	// Replenish (contract 9.1): C (token, action=add, value amount or unit count) + ContinuID I atom.
	// Signed by the identity's USER wallet like initTokenCreation; creditedWallet is the identity's
	// existing wallet for the token (or a fresh one). units non-empty = stackable / non-fungible:
	// the C value is the unit count and the new units ride as tokenUnits triples.
	std::vector<Atom> initTokenReplenish(const Wallet &sourceWallet, const Wallet &creditedWallet, const std::string &amount, const std::vector<TokenUnit> &units = {});
	// Stackable fusion (contract 9.2): V (source -B, the fused units), V (burn +(M-1)), F (recipient +1,
	// the new unit N), V (remainder +(B-M), the kept units). No ContinuID atom. fusedTokenUnitIds are in
	// caller order and must name >= 2 units of sourceWallet; newTokenUnitId must not exist in it.
	std::vector<Atom> initTokenFusion(const Wallet &sourceWallet, const Wallet &recipientWallet, const Wallet &remainderWallet, const std::vector<std::string> &fusedTokenUnitIds, const std::string &newTokenUnitId);
	std::vector<Atom> initAuthorization(const Wallet &sourceWallet, bool encrypt = false);

	// compressed mirrors JS Molecule.sign({ compressed = true }) and the C SDK's
	// knishio_molecule_sign(..., bool compressed): the hex OTS (2048 for v1, 8192 for v2) is
	// base64-compressed (1368 / 5464 characters) before being chunked across the atoms. Every
	// other SDK ships this form; do not pass false unless an uncompressed hex OTS is explicitly
	// required. The key is derived at signingOtsVersion(). Throws
	// knishio::SignatureMalformedException when the molecular hash is not 64 characters of [0-9a-g].
	std::string sign(const std::string &secret, bool anonymous = false, bool compressed = true);

	// OTS version this molecule signs with: the source wallet's version, or 1 without one.
	[[nodiscard]] int signingOtsVersion() const;

	std::string toJson() const;

	static Molecule jsonToObject(const std::string &json);
	// int8_t, NOT char: plain `char` is UNSIGNED on aarch64 (and every other target whose ABI
	// says so), which turns the -8..8 symbol values into 248..255 and makes the WOTS+ chain
	// counts 8 - n / 8 + n diverge from every other SDK. The type is the invariant here.
	static std::vector<int8_t> enumerate(const std::string &hash);
	static std::vector<int8_t> normalize(const std::vector<int8_t> &mappedHashArray);
	static bool verify(const Molecule &molecule);
	static bool verifyMolecularHash(const Molecule &molecule);
	// Verifies the one-time signature (16 or 64 chains). Throws knishio::SignatureMalformedException
	// for a malformed molecular hash or signature and knishio::SignatureMismatchException when the
	// signature does not match atoms[0].walletAddress.
	static void verifyOts(const Molecule &molecule);
	static bool verifyTokenIsotopeV(const Molecule &molecule);
	// JS CheckMolecule.continuId: a molecule signed by a USER wallet (atoms[0].token == "USER") must
	// carry a ContinuID (I) atom. Part of check(), not verify(); the validator's Tier 1 enforces it too.
	static bool verifyContinuId(const Molecule &molecule);
	// Pre-submit check (contract 9.7) of a signed molecule: throws AtomsNotFoundException when the
	// molecule has no atoms or lacks its ContinuID atom (JS AtomsMissingException),
	// std::runtime_error when the hash or conservation do not verify, and verifyOts()'s
	// SignatureMalformedException / SignatureMismatchException unchanged.
	static void check(const Molecule &molecule);
	// Conservation + meta-shape validation for B/F (buffer-family) molecules. Mirrors
	// isotopeB()/isotopeF() in the JS reference; verifyTokenIsotopeV() delegates to this
	// when it skips the V-only sum, so that the skip is not an unconditional accept.
	static bool verifyCrossIsotopeConservation(const Molecule &molecule);

	// Builds a molecule from its JSON exactly as a validator's GraphQL API serves it (bundleHash,
	// tokenSlug, metasJson, RFC 3339 createdAt, optional atom versions). Throws on malformed input.
	static Molecule fromServerData(const std::string &servedJson);
	// Verifies a served molecule: the molecular hash, then check(). When the hash does not match
	// and no served atom carries a version, retries with version "4" on every atom, then "3".
	// Never throws; malformed input gives verified = false with an error.
	static ServedVerification verifyFromServerData(const std::string &servedJson);
	// Served createdAt as a millisecond string: digit strings unchanged, RFC 3339 timestamps
	// converted to epoch milliseconds (fraction truncated to 3 digits, offset applied), other
	// strings unchanged; an empty string is absent.
	static std::optional<std::string> toSignedTimestamp(const std::string &createdAt);
	static std::string toSignedTimestamp(long long createdAt);

private:
	// Appends the ContinuID (I-isotope) atom, mirroring JS Molecule.addContinuIdAtom():
	// the I-atom is sourced from this->remainderWallet (position/address/bundle) and carries
	// meta [previousPosition = sourceWallet.position, pubkey, characters].
	void addContinuIdAtom(const Wallet &sourceWallet, int index);

public:
	std::string					molecularHash;
	std::string					cellSlug;
	std::string					bundle;
	std::string					status;
	std::vector<Atom>			atoms;
	std::chrono::milliseconds	createdAt;

	// Cross-SDK compatibility fields (matches JavaScript, TypeScript, etc.)
	std::shared_ptr<Wallet>		sourceWallet = nullptr;
	std::shared_ptr<Wallet>		remainderWallet = nullptr;
};

} // namespace KnishIO

