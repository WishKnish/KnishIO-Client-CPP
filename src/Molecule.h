#pragma once

#include <cstdint>  // int8_t in the enumerate/normalize signatures below
#include <memory>

#include "Atom.h"

namespace KnishIO {

class Wallet;

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
	// Withdraw: B (source -balance) -> N x V (recipient shadow +amount) -> B (remainder +(balance-Σ)).
	// recipientWallets is parallel to amounts; full-balance debit (JS parity) conserves for partial
	// withdraws too: -balance + Σamounts + (balance-Σ) == 0.
	std::vector<Atom> initWithdrawBuffer(const Wallet &sourceWallet, const std::vector<Wallet> &recipientWallets, const std::vector<std::string> &amounts, const Wallet &remainderWallet);
	std::vector<Atom> initAuthorization(const Wallet &sourceWallet, bool encrypt = false);

	// compressed mirrors JS Molecule.sign({ compressed = true }) and the C SDK's
	// knishio_molecule_sign(..., bool compressed): the 2048-hex OTS is base64-compressed
	// to 1368 characters before being chunked across the atoms. Every other SDK ships
	// this form; do not pass false unless an uncompressed hex OTS is explicitly required.
	std::string sign(const std::string &secret, bool anonymous = false, bool compressed = true);

	std::string toJson() const;

	static Molecule jsonToObject(const std::string &json);
	// int8_t, NOT char: plain `char` is UNSIGNED on aarch64 (and every other target whose ABI
	// says so), which turns the -8..8 symbol values into 248..255 and makes the WOTS+ chain
	// counts 8 - n / 8 + n diverge from every other SDK. The type is the invariant here.
	static std::vector<int8_t> enumerate(const std::string &hash);
	static std::vector<int8_t> normalize(const std::vector<int8_t> &mappedHashArray);
	static bool verify(const Molecule &molecule);
	static bool verifyMolecularHash(const Molecule &molecule);
	static bool verifyOts(const Molecule &molecule);
	static bool verifyTokenIsotopeV(const Molecule &molecule);
	// Conservation + meta-shape validation for B/F (buffer-family) molecules. Mirrors
	// isotopeB()/isotopeF() in the JS reference; verifyTokenIsotopeV() delegates to this
	// when it skips the V-only sum, so that the skip is not an unconditional accept.
	static bool verifyCrossIsotopeConservation(const Molecule &molecule);

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

