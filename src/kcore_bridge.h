// Internal: eligibility gates in front of the optional KnishIO Crypto Core (kcore).
// Compiled only when the library is built with KNISHIO_USE_KCORE=ON (KNISHIO_HAVE_KCORE=1).
// Every helper returns false for input kcore must not see (uppercase or non-hex text, wrong
// lengths, out-of-range counts) or when kcore itself fails; the caller then runs its existing
// code, so a verifier's verdict never depends on whether kcore is linked.
#pragma once

#ifdef KNISHIO_HAVE_KCORE

#include <kcore.h>

#include <string>
#include <vector>

namespace KnishIO::kcore_bridge {

inline bool isLowerHex(const std::string &s, size_t length)
{
	if (s.size() != length) {
		return false;
	}
	for (const char c : s) {
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
			return false;
		}
	}
	return true;
}

// WOTS+ address of a 2048-hex key. False when the key is ineligible or kcore fails.
inline bool wotsAddress(const std::string &key, std::string &address)
{
	if (!isLowerHex(key, 2048)) {
		return false;
	}
	char out[64];
	if (kcore_wots_address(key.c_str(), out) != 0) {
		return false;
	}
	address.assign(out, 64);
	return true;
}

// Advances each 128-hex chunk counts[i] times and returns the concatenation. Requires 1..64
// chunks of exactly 128 lowercase hex characters and every count in 0..64.
inline bool chainsHex(const std::vector<std::string> &chunks, const std::vector<int> &counts, std::string &out)
{
	const size_t n = chunks.size();
	if (n < 1 || n > 64 || counts.size() != n) {
		return false;
	}
	std::string buf;
	buf.reserve(n * 128);
	for (size_t i = 0; i < n; i++) {
		if (!isLowerHex(chunks[i], 128) || counts[i] < 0 || counts[i] > 64) {
			return false;
		}
		buf += chunks[i];
	}
	if (kcore_chains_hex(buf.data(), counts.data(), n, 4) != 0) {
		return false;
	}
	out = std::move(buf);
	return true;
}

} // namespace KnishIO::kcore_bridge

#endif // KNISHIO_HAVE_KCORE
