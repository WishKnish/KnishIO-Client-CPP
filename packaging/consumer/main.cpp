// Release-package consumer smoke: prints the bundle hash of a secret through the installed
// headers and library. packaging/check-release-package.sh builds it three ways (plain -I/-L,
// find_package shared, find_package static) and compares the output with SHAKE256 of the secret.
#include <knishio/KnishIOClient.h>
#include <knishio/Wallet.h>

#include <iostream>
#include <string>

int main(int argc, char **argv) {
    const std::string secret = argc > 1 ? argv[1] : "knishio-consumer-smoke";
    std::cout << KnishIO::Wallet::generateBundleHash(secret) << '\n';
    return 0;
}
