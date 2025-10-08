/**
 * Example: Query Balance
 * 
 * This example demonstrates how to use the KnishIO C++ SDK to query
 * wallet balance information from a Knish.IO node.
 */

#include <iostream>
#include <memory>
#include <string>
#include "src/KnishIOClient.h"
#include "src/exception/KnishIOException.h"
#include "include/http/GraphQLClient.h"
#include "include/query/QueryBalance.h"
#include "include/response/Response.h"

int main(int argc, char* argv[]) {
    try {
        std::cout << "=== KnishIO C++ SDK - Query Balance Example ===" << std::endl;
        std::cout << "SDK Version: " << knishio::KnishIOClient::getVersion() << std::endl << std::endl;
        
        // Step 1: Initialize the client with node URIs
        std::vector<std::string> nodeUris = {
            "https://node1.knish.io",
            "https://node2.knish.io"
        };
        
        // If command line argument provided, use it as the node URI
        if (argc > 1) {
            nodeUris = {argv[1]};
            std::cout << "Using custom node URI: " << argv[1] << std::endl;
        } else {
            std::cout << "Using default node URIs" << std::endl;
        }
        
        auto client = knishio::KnishIOClient::Builder()
            .uris(nodeUris)
            .enableLogging(true)
            .timeout(std::chrono::milliseconds(10000))
            .build();
        
        std::cout << "Client initialized successfully!" << std::endl << std::endl;
        
        // Step 2: Generate or use a test secret
        std::string secret = knishio::KnishIOClient::generateSecret(2048);
        client->setSecret(secret);
        std::string bundleHash = client->getBundle();
        
        std::cout << "Test wallet created:" << std::endl;
        std::cout << "  Bundle Hash: " << bundleHash << std::endl;
        std::cout << "  Secret (first 32 chars): " << secret.substr(0, 32) << "..." << std::endl << std::endl;
        
        // Step 3: Create GraphQL client and Query
        // Note: In a real implementation, this would be integrated into KnishIOClient
        knishio::http::GraphQLClient graphqlClient(nodeUris[0], 10000, 3);
        
        // Step 4: Create and execute a balance query
        std::cout << "Querying balance for bundle: " << bundleHash << std::endl;
        
        knishio::query::QueryBalance balanceQuery(&graphqlClient);
        
        // Query by bundle hash and token
        try {
            nlohmann::json response = balanceQuery.execute(
                std::nullopt,      // address
                bundleHash,        // bundleHash
                "USER",           // token
                std::nullopt,      // position
                std::nullopt       // type
            );
            
            std::cout << "\nQuery executed successfully!" << std::endl;
            std::cout << "Response:" << std::endl;
            std::cout << response.dump(2) << std::endl;
            
            // Parse balance information if available
            if (response.contains("data") && response["data"].contains("Balance")) {
                auto balance = response["data"]["Balance"];
                if (!balance.is_null()) {
                    std::cout << "\nBalance Information:" << std::endl;
                    if (balance.contains("address")) {
                        std::cout << "  Address: " << balance["address"] << std::endl;
                    }
                    if (balance.contains("tokenSlug")) {
                        std::cout << "  Token: " << balance["tokenSlug"] << std::endl;
                    }
                    if (balance.contains("amount")) {
                        std::cout << "  Amount: " << balance["amount"] << std::endl;
                    }
                    if (balance.contains("position")) {
                        std::cout << "  Position: " << balance["position"] << std::endl;
                    }
                } else {
                    std::cout << "\nNo balance found for this wallet (expected for new wallets)" << std::endl;
                }
            }
            
        } catch (const knishio::NetworkException& e) {
            std::cerr << "Network error: " << e.what() << std::endl;
            std::cerr << "Note: Make sure the node URI is accessible" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Query error: " << e.what() << std::endl;
        }
        
        // Step 5: Demonstrate async query
        std::cout << "\n--- Async Query Example ---" << std::endl;
        std::cout << "Starting async balance query..." << std::endl;
        
        auto futureResult = balanceQuery.executeAsync({
            {"bundleHash", bundleHash},
            {"token", "USER"}
        });
        
        std::cout << "Waiting for async response..." << std::endl;
        try {
            auto asyncResponse = futureResult.get();
            std::cout << "Async query completed!" << std::endl;
            std::cout << "Response size: " << asyncResponse.dump().length() << " bytes" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Async query error: " << e.what() << std::endl;
        }
        
        std::cout << "\n=== Example completed ===" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}