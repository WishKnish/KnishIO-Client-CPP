#include "src/KnishIOClient.h"
#include <iostream>

int main() {
    try {
        // Create client using builder pattern
        auto client = knishio::KnishIOClient::Builder()
            .uris({"https://node1.knish.io", "https://node2.knish.io"})
            .cellSlug("test-cell")
            .enableLogging(true)
            .timeout(std::chrono::milliseconds(10000))
            .maxRetries(3)
            .build();
        
        std::cout << "KnishIO Client initialized successfully!" << std::endl;
        std::cout << "SDK Version: " << knishio::KnishIOClient::getVersion() << std::endl;
        
        // Generate a test secret
        std::string secret = knishio::KnishIOClient::generateSecret(2048);
        std::cout << "Generated secret (first 32 chars): " << secret.substr(0, 32) << "..." << std::endl;
        
        // Set secret and get bundle
        client->setSecret(secret);
        std::cout << "Bundle hash: " << client->getBundle() << std::endl;
        
        // Test molecule creation
        // Note: Using raw pointer since Molecule is forward-declared
        Molecule* molecule = client->createMolecule();
        if (molecule) {
            std::cout << "Molecule created successfully!" << std::endl;
            delete molecule; // Clean up manually
        }
        
        std::cout << "\nAll basic operations completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}