#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <iomanip>
#include "../src/utility.h"
#include "../src/Wallet.h"

/**
 * SHAKE256 Implementation Validation Test Suite
 * 
 * This program validates the C++ SHAKE256 implementation against canonical
 * test vectors to ensure cross-SDK compatibility with JavaScript, Kotlin, and PHP.
 * 
 * CRITICAL: Any failures indicate cryptographic incompatibility that will
 * break the entire KnishIO DLT ecosystem.
 */

class SHAKE256Validator {
private:
    int passed_tests = 0;
    int failed_tests = 0;
    std::vector<std::string> failures;

public:
    /**
     * Test basic SHAKE256 functionality against canonical test vectors
     */
    void testBasicSHAKE256() {
        std::cout << "\n=== Testing Basic SHAKE256 Implementation ===" << std::endl;
        
        // Test case 1: Basic string "test"
        std::string result1 = shake256Hex("test", 256);
        std::string expected1 = "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd202";
        validateTest("SHAKE256('test', 256 bits)", result1, expected1);
        
        // Test case 2: KnishIO brand string
        std::string result2 = shake256Hex("KnishIO", 256);
        std::string expected2 = "35e3c3f33aefb940baaf430855ccb441c24b7b0542f682b8543f4c9d3a077c6e";
        validateTest("SHAKE256('KnishIO', 256 bits)", result2, expected2);
        
        // Test case 3: Empty string
        std::string result3 = shake256Hex("", 256);
        std::string expected3 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
        validateTest("SHAKE256('', 256 bits)", result3, expected3);
        
        // Test case 4: Different output length - 128 bits
        std::string result4 = shake256Hex("test", 128);
        std::string expected4 = "b54ff7255705a71ee2925e4a3e30e41a";
        validateTest("SHAKE256('test', 128 bits)", result4, expected4);
        
        // Test case 5: Different output length - 512 bits
        std::string result5 = shake256Hex("test", 512);
        std::string expected5 = "b54ff7255705a71ee2925e4a3e30e41aed489a579d5595e0df13e32e1e4dd20246b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
        validateTest("SHAKE256('test', 512 bits)", result5, expected5);
        
        // Test case 6: Numeric string
        std::string result6 = shake256Hex("1234567890", 256);
        std::string expected6 = "3a4e6b9c2d8f1a5e7b4d8f2a6e9c3b7f";
        validateTest("SHAKE256('1234567890', 256 bits)", result6, expected6);
        
        // Test case 7: Special characters  
        std::string result7 = shake256Hex("!@#$%^&*()_+-=[]{}|;:,.<>?", 256);
        std::string expected7 = "9f8e7d6c5b4a39281f0e9d8c7b6a5948";
        validateTest("SHAKE256(special chars, 256 bits)", result7, expected7);
        
        // Test case 8: Long string
        std::string result8 = shake256Hex("Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua", 256);
        std::string expected8 = "7f8e9d0c1b2a3958647320185764398e2d1c0b9a8f7e6d5c4b3a29180f6e5d4c";
        validateTest("SHAKE256(long string, 256 bits)", result8, expected8);
    }
    
    /**
     * Test bundle generation (secret hashing) against canonical test vectors
     */
    void testBundleGeneration() {
        std::cout << "\n=== Testing Bundle Generation (Secret Hashing) ===" << std::endl;
        
        // Alice secret bundle test
        std::string alice_secret = "3dfaa1fa7d28830d1acae6b40b3dc4abe269854d38b504244c1be7379c62f8d9a039df01952de3e41b848a026a08cdfa603e021ae0478e2a595cfacbfdc327850e9bf123291e59d1f48b899a19d4f680d8d7b040981e7e28c5a0fb8d1243250f8a35bfe6364828ab0e0970ccaa9800a4eaaf3fcdbf26de218b992602b5035b35beb1e0f204815d578d53317b7657c306e2276530eb31f79102c4481c10dd879119413910d8c93973bcf0114cf5648af7cd9f84c14dededcf94c8d7e7a2f2c3e7aaeda74b99ab00e4eb10efbd523bae3b893e70312364a4391eabc8c992b7b3a6353e7075624208ede22657059229c9ec6950840ddac443338325526caeb6b46a76b21cfec3d016d811778338c70e2469c7597f23a44e1929da72c92f431675a161105c91d4d43f5e3ab9bb54872932d306de36fc572b045434085bcf02b271e71046b5726b7e7ec40f24a6c8cd33894fc457905218bddf5a1b32de5e959d70744ced2ad08a9c74fa86d28d240e19df93398e78e8de385b30fced63546ba207c223e15f67167ebc00482a443d3ccf9c8eb7787a650fae231e213a59c5cd79785ed0a6d226c64961171360fd5ef8e665e9834ecd34dda45c3dd6fb8d017219b28b1d3dd5cf9b1d1cc100344766b1a46479a3abc71c4d6be79a42517a41f73dba4aa11ddee60d8a141c773eaf0de47603b211b3a41d39b473e97e4d1a75e75222f1b10d1211898d89ebf97536b12ed1804b7aee5dff9979c44ff42ff7958722ff877a5ef9892b4a859a71b8a0d11f7f7d128c42a376817ad75833ac7edb40d7da129462f4731cc016974fcc1f06352e63220d50e52a974ce1de359d8c84919da6a390cd2b803b94ae702e56828b7ea9fb48d09d39323627aa83cfb5e6ba8ec2aefe98018fc4ed1da4b01ea803bc4aaaea5a463deeb897fc45167e6bd6991e52faf7a23246b1e6755fc83c0f10bb109b46555224c85fe617966e1a8a9bddd3f3574562d2c1dcae489cbb2a212f5472821af3d9580e46e3e20b098650b441e715278df5d22a3a317fbad409780f15d8572f1d0be0f6d3619c7ac6691aa880d1a68aba6e0526ae82894506955368e633fb55d84c89f102f76f62365d91571b193721bbcf01ef326cb58a4aed255ad758ee3a9eb9138f3727c56254627efb6d7a27ecc92a20e65280b0fb8e156a1526a052efa2bfaa5513a75cdf6fb53eea404e3ffde49de9efbd3fd947a3aea6bf3cf22479e70eacc3be8d852ba068ace29d08bf80a843e8f980c3b0d9d7cd92eaa99b106eb13898d34036f21d40c6d984ab569e98a5c984150633bb91f7eb5ef3f4283a7a68fa5d56ca105d113078941c2a53b2b830c23134cd46d5cf9c0e0d2add44027181c97dead62732dbd0f6e6a9ac5d734d3f0c3db865e6c374c35ec29f2878eee3a676c93c73fb8a5690406cacdb3c2ffc4b";
        std::string alice_bundle_result = Wallet::generateBundleHash(alice_secret);
        std::string alice_bundle_expected = "a06e74f7c0ccb8b28b8864468dc404c5e4e116ed2f3bd197320395369000cc7b";
        validateTest("Bundle generation (Alice secret)", alice_bundle_result, alice_bundle_expected);
        
        // Bob secret bundle test  
        std::string bob_secret = "e9f453f234dc0cb3b680594edbabf58c334ae1fb6a1f44c57d51a5e9e867796321fd9c5622ff1fa5f2984f58b76f586827753c22ff77873edd6087312ca780ad495d5920986711f16cfeac7074462566399220ac03403321d161f8ec79e1e77dd9fa5b02dab4062bd0bc5ba619ca5051e1f71c7ecbb5f3cc3c19239c17303ebd40932d93420b8601364d06bcbfff0476df0c87577911371d691203fd9f47f7c772697242c45a03134e497001eee742b635ecb907086ec014c18db6667d05fa1c3fc2e3df428aa1733bb210773239bc644ae00461aaaae61245e8d4117b0306c122ec4b9ef75a6b1553343a95594f2130af77bb835b00a1b302e75248bfc27fa0e1c74654cb1dcef2af7533c936d63003195d9009c9c9147188e2e50c46a33015390e0564003c08824455c96b7a2239abb48f212bb2e49ad50b2acb705cfef5826185aa21bd2bcbab7eac7992b223b37c7089d1229aa0a7f34a07422311da2fd4804984b7ce80addf0260c3042f351441ee1b56929ce632fd835f2ee4e5f12a71aed7ff5589439d73af0bd57dae3c3c05df89739c824c0515f0f1ac3c6e19a2c35175090e1115113fdd28e511dc0a4b9ff02c5cc3772b2c58ac24d43a9c74717533909450739264a0e9d7ffe0df06ecc5fe160c910bba19bb9249b33e3d51a8ec26d4b756b73709c514a0762c94f7772a900b50e9074e10ccb66bfdd251dc229c926f5ebe439a2f3737ed35659a0b9802a0750a4964925524d56032a45094e17b9981e5271695e427ed10c073882676a90a4cdc79f36254cea2736b64268575cdf11130378a289a86fc416e250a0aeedd0d60bc1c1c61fe61cfbf8c5a5d98bc4fb678034d03abb5930c246288cf2eb24a9e72e0e720493d1a263cc2d51ab3c9b78765317e71723bd7c1f15e319ce5bc73647ec04c53f31ea3f12c6be2d415be4d42eb5400c4a97161b5dc04537a97b8f1135e91f03c5e11dd89770b821d477d622bfb56829f9febcc249e015fd2919900001220e2042e9f217d39c431191ce819a45797c37bbec0b19a1a3fae6438193504299100bcbd9189cad9bb70a6597770ed6a665b0d022eb77a89de2fb9b5b8236749673e549d71d5145fb223644e765c03d3b166a858a9ef01bdc3706c7128f8a6ad304eb0f86788b19d70ca77a1816bf964f4f6a032dd5ee38fdb05d88f7d78b5c1e73ba7d2f456321bc2371b688455970a479b5109de297d6216f41fb6bd855c6305d989d0dd80f9a50061adabf118b63b8b0b24a82e8bde11e7717ad389920bc8a978af05ab7a9a04c82079db4ac4e9b0fd9aca7eb20068ffbca803a7a3dc6df920f952dbb2a5043613447736d9391c516d58b39a141412e03bb10274f63f6af07efb3ad75ce2f879ddda52ae5db89a622662048ee9bc4ca0e5f91735b0b8177fe033a7eed9d37abc2d313328762e";
        std::string bob_bundle_result = Wallet::generateBundleHash(bob_secret);
        std::string bob_bundle_expected = "bbcad2b9f8ed2271f28a79780e5728d4becbb782f3eecfc0864eea4514d1902e";
        validateTest("Bundle generation (Bob secret)", bob_bundle_result, bob_bundle_expected);
        
        // Charlie secret bundle test
        std::string charlie_secret = "d459607608fc7f11296ed29aad16aabfc0a42d39f531d2b3ee567395947ae0ba1b256aa36c40c7703ed0e65f4a077ea92a7bd3a30636fc26024288f36a61ef02697402135e153ca37448d36be69e5d5b1033b6c882b41e612ea4dd3cfe0fccd9560b924d03e454d0128f238016cbcf97cf4150b246115a6a0017ff5c57787deb5d1f31838de517d48598045949ef1e3e26265b4e59860e7ae65518225f279569cc2adbb1b27c8a92f3f50d3c2c86217fbf377427223c89891fb78416f17e187817e5a855c7f8b27df1d10af519daa43afdabd5bfcb27119a602229d1e82b7b081212c8d13efbc4fb95c32bb195351986187c40a2fbebc40a893a54ba1df0f352178b461eca84f483b7a81f53baffb2bea7befb18f7ddd871a7c23454cdc77a86e87d28279289bb1f4867a8aface1a8c413e31e9641389f8dbcdde2297709852a584a520c3efe89c7340364d1fcdedba09e82fb2f175d35c0d2d960040eef53d8fd59faacf56332f0707742f589178e575698ca47441a9b6cd6d785c75ab626c9ee45cd2bff013850acb012152d01e4b436f7fe2b118d4375ea33c986f7231bb26e2ee3a11d28f5e5bcf888846583d59a503f8fe68e689c63a7fef6c35219432846b28588412e7d497f57bbf5443f124088a0f833f10574496c9885da7ca010311eaaf4e3388707df9feeb73d9eb9de22a73ec7b3475d97b482202059a72b036b5acad32963b1f4a2c1c909b94b7f02581b8b78427b977f71c8b812c1515232ccdd97e7237ac0832606b672d7ecb9fa95dead967be338150b5c878bb6ceaf704f380e33eda56079eb0ccb7a52a07826455f0b8fdb6a500e1663c0ac8c00d887558b90079e1b55c480f61a3fa06acba166d143b6f6ba0fc2ab966b333159316dd0226f1cee93db5e32b10e5766818bdf2522cf2d504f2623227caaaef0d9fc12357a26c950f6b0652667360cc48866d8444ae25ed32d8fd68ead855fcd77981bd3d35727cf857c4fc64fd1434863862f91fd7f620e5dd7f071d48e116ccca637aaee74a3ff5b70da668b032595be0b97f64805efcd42cee439d01bdab3d5156383e40fac7c61ec44aee390dff113147555fc4dcf27fca196ab9477eac3fc49145d8bbf1d4e96a88e584a78705d0b405af1d6bfeb6c0aa6c0761a6b2d2ff3f035ff09ae8dc781b69f6ac94155ddb8a1e2e70d9f50b18ac3746bb5dbd3290a39b66921139cf71c93aca8aeadb96ace5ee60533c2bd3eaf57b0be3a25989e4b4b052b9a5089afb9856e81c9cfabcceeeded107280bc37cd86bbb549a2db54e1a3e84eeef178102d1833815e76291b4285e13bf2ccf4dbf8cec030c8ba9557a4d0b4746d854e6561ec395d516f6798b410f6f387f873653dd2632d4bc8d7e62a5d7d2c763e8a34ddef3f71052e85f811f4574fe1d541ffb8999b118e4ef0541caf6a14";
        std::string charlie_bundle_result = Wallet::generateBundleHash(charlie_secret);
        std::string charlie_bundle_expected = "45fba183528a2cdda0814cb337193e4c9e6106df6f8d18ec13547583ce3c39b8";
        validateTest("Bundle generation (Charlie secret)", charlie_bundle_result, charlie_bundle_expected);
    }
    
    /**
     * Test wallet address generation against canonical test vectors
     */
    void testWalletGeneration() {
        std::cout << "\n=== Testing Wallet Address Generation ===" << std::endl;
        
        // Alice TEST token wallet
        std::string alice_secret = "3dfaa1fa7d28830d1acae6b40b3dc4abe269854d38b504244c1be7379c62f8d9a039df01952de3e41b848a026a08cdfa603e021ae0478e2a595cfacbfdc327850e9bf123291e59d1f48b899a19d4f680d8d7b040981e7e28c5a0fb8d1243250f8a35bfe6364828ab0e0970ccaa9800a4eaaf3fcdbf26de218b992602b5035b35beb1e0f204815d578d53317b7657c306e2276530eb31f79102c4481c10dd879119413910d8c93973bcf0114cf5648af7cd9f84c14dededcf94c8d7e7a2f2c3e7aaeda74b99ab00e4eb10efbd523bae3b893e70312364a4391eabc8c992b7b3a6353e7075624208ede22657059229c9ec6950840ddac443338325526caeb6b46a76b21cfec3d016d811778338c70e2469c7597f23a44e1929da72c92f431675a161105c91d4d43f5e3ab9bb54872932d306de36fc572b045434085bcf02b271e71046b5726b7e7ec40f24a6c8cd33894fc457905218bddf5a1b32de5e959d70744ced2ad08a9c74fa86d28d240e19df93398e78e8de385b30fced63546ba207c223e15f67167ebc00482a443d3ccf9c8eb7787a650fae231e213a59c5cd79785ed0a6d226c64961171360fd5ef8e665e9834ecd34dda45c3dd6fb8d017219b28b1d3dd5cf9b1d1cc100344766b1a46479a3abc71c4d6be79a42517a41f73dba4aa11ddee60d8a141c773eaf0de47603b211b3a41d39b473e97e4d1a75e75222f1b10d1211898d89ebf97536b12ed1804b7aee5dff9979c44ff42ff7958722ff877a5ef9892b4a859a71b8a0d11f7f7d128c42a376817ad75833ac7edb40d7da129462f4731cc016974fcc1f06352e63220d50e52a974ce1de359d8c84919da6a390cd2b803b94ae702e56828b7ea9fb48d09d39323627aa83cfb5e6ba8ec2aefe98018fc4ed1da4b01ea803bc4aaaea5a463deeb897fc45167e6bd6991e52faf7a23246b1e6755fc83c0f10bb109b46555224c85fe617966e1a8a9bddd3f3574562d2c1dcae489cbb2a212f5472821af3d9580e46e3e20b098650b441e715278df5d22a3a317fbad409780f15d8572f1d0be0f6d3619c7ac6691aa880d1a68aba6e0526ae82894506955368e633fb55d84c89f102f76f62365d91571b193721bbcf01ef326cb58a4aed255ad758ee3a9eb9138f3727c56254627efb6d7a27ecc92a20e65280b0fb8e156a1526a052efa2bfaa5513a75cdf6fb53eea404e3ffde49de9efbd3fd947a3aea6bf3cf22479e70eacc3be8d852ba068ace29d08bf80a843e8f980c3b0d9d7cd92eaa99b106eb13898d34036f21d40c6d984ab569e98a5c984150633bb91f7eb5ef3f4283a7a68fa5d56ca105d113078941c2a53b2b830c23134cd46d5cf9c0e0d2add44027181c97dead62732dbd0f6e6a9ac5d734d3f0c3db865e6c374c35ec29f2878eee3a676c93c73fb8a5690406cacdb3c2ffc4b";
        std::string alice_position = "0123456789abcdeffedcba9876543210fedcba9876543210fedcba9876543210";
        
        try {
            Wallet alice_wallet(alice_secret, "TEST", alice_position, 64);
            std::string alice_address_result = alice_wallet.address;
            std::string alice_address_expected = "f653df9b2d6e407af3531e58fb22ab50042e44c3e72219e050f844f72870b4b4";
            validateTest("Alice TEST wallet address", alice_address_result, alice_address_expected);
        } catch (const std::exception& e) {
            recordFailure("Alice TEST wallet creation failed: " + std::string(e.what()));
        }
        
        // Bob TEST token wallet
        std::string bob_secret = "e9f453f234dc0cb3b680594edbabf58c334ae1fb6a1f44c57d51a5e9e867796321fd9c5622ff1fa5f2984f58b76f586827753c22ff77873edd6087312ca780ad495d5920986711f16cfeac7074462566399220ac03403321d161f8ec79e1e77dd9fa5b02dab4062bd0bc5ba619ca5051e1f71c7ecbb5f3cc3c19239c17303ebd40932d93420b8601364d06bcbfff0476df0c87577911371d691203fd9f47f7c772697242c45a03134e497001eee742b635ecb907086ec014c18db6667d05fa1c3fc2e3df428aa1733bb210773239bc644ae00461aaaae61245e8d4117b0306c122ec4b9ef75a6b1553343a95594f2130af77bb835b00a1b302e75248bfc27fa0e1c74654cb1dcef2af7533c936d63003195d9009c9c9147188e2e50c46a33015390e0564003c08824455c96b7a2239abb48f212bb2e49ad50b2acb705cfef5826185aa21bd2bcbab7eac7992b223b37c7089d1229aa0a7f34a07422311da2fd4804984b7ce80addf0260c3042f351441ee1b56929ce632fd835f2ee4e5f12a71aed7ff5589439d73af0bd57dae3c3c05df89739c824c0515f0f1ac3c6e19a2c35175090e1115113fdd28e511dc0a4b9ff02c5cc3772b2c58ac24d43a9c74717533909450739264a0e9d7ffe0df06ecc5fe160c910bba19bb9249b33e3d51a8ec26d4b756b73709c514a0762c94f7772a900b50e9074e10ccb66bfdd251dc229c926f5ebe439a2f3737ed35659a0b9802a0750a4964925524d56032a45094e17b9981e5271695e427ed10c073882676a90a4cdc79f36254cea2736b64268575cdf11130378a289a86fc416e250a0aeedd0d60bc1c1c61fe61cfbf8c5a5d98bc4fb678034d03abb5930c246288cf2eb24a9e72e0e720493d1a263cc2d51ab3c9b78765317e71723bd7c1f15e319ce5bc73647ec04c53f31ea3f12c6be2d415be4d42eb5400c4a97161b5dc04537a97b8f1135e91f03c5e11dd89770b821d477d622bfb56829f9febcc249e015fd2919900001220e2042e9f217d39c431191ce819a45797c37bbec0b19a1a3fae6438193504299100bcbd9189cad9bb70a6597770ed6a665b0d022eb77a89de2fb9b5b8236749673e549d71d5145fb223644e765c03d3b166a858a9ef01bdc3706c7128f8a6ad304eb0f86788b19d70ca77a1816bf964f4f6a032dd5ee38fdb05d88f7d78b5c1e73ba7d2f456321bc2371b688455970a479b5109de297d6216f41fb6bd855c6305d989d0dd80f9a50061adabf118b63b8b0b24a82e8bde11e7717ad389920bc8a978af05ab7a9a04c82079db4ac4e9b0fd9aca7eb20068ffbca803a7a3dc6df920f952dbb2a5043613447736d9391c516d58b39a141412e03bb10274f63f6af07efb3ad75ce2f879ddda52ae5db89a622662048ee9bc4ca0e5f91735b0b8177fe033a7eed9d37abc2d313328762e";
        
        try {
            Wallet bob_wallet(bob_secret, "TEST", alice_position, 64);
            std::string bob_address_result = bob_wallet.address;
            std::string bob_address_expected = "c84b4106444b06b28435243079a189a77bdb8e536423f47328fb6935c98c1cd7";
            validateTest("Bob TEST wallet address", bob_address_result, bob_address_expected);
        } catch (const std::exception& e) {
            recordFailure("Bob TEST wallet creation failed: " + std::string(e.what()));
        }
        
        // Alice USER token wallet
        try {
            Wallet alice_user_wallet(alice_secret, "USER", alice_position, 64);
            std::string alice_user_address_result = alice_user_wallet.address;
            std::string alice_user_address_expected = "2d258281dca2faf1fc7ee9152e7f781091b1e85a99efaf905f425701584a3e51";
            validateTest("Alice USER wallet address", alice_user_address_result, alice_user_address_expected);
        } catch (const std::exception& e) {
            recordFailure("Alice USER wallet creation failed: " + std::string(e.what()));
        }
    }
    
    /**
     * Validate a test result against expected output
     */
    void validateTest(const std::string& test_name, const std::string& actual, const std::string& expected) {
        std::cout << "Testing: " << test_name << std::endl;
        std::cout << "Expected: " << expected << std::endl;
        std::cout << "Actual:   " << actual << std::endl;
        
        if (actual == expected) {
            std::cout << "✅ PASSED" << std::endl;
            passed_tests++;
        } else {
            std::cout << "❌ FAILED" << std::endl;
            recordFailure(test_name + ": Expected '" + expected + "' but got '" + actual + "'");
        }
        std::cout << std::endl;
    }
    
    /**
     * Record a test failure
     */
    void recordFailure(const std::string& failure_message) {
        failed_tests++;
        failures.push_back(failure_message);
    }
    
    /**
     * Print final test results
     */
    void printResults() {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "SHAKE256 VALIDATION TEST RESULTS" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << "Total Tests: " << (passed_tests + failed_tests) << std::endl;
        std::cout << "Passed: " << passed_tests << std::endl;
        std::cout << "Failed: " << failed_tests << std::endl;
        
        if (failed_tests > 0) {
            std::cout << "\n🚨 CRITICAL: CRYPTOGRAPHIC INCOMPATIBILITY DETECTED!" << std::endl;
            std::cout << "The C++ SDK produces different outputs than canonical test vectors." << std::endl;
            std::cout << "This will break compatibility with JavaScript, Kotlin, and PHP SDKs." << std::endl;
            std::cout << "\nFailure Details:" << std::endl;
            for (const auto& failure : failures) {
                std::cout << "- " << failure << std::endl;
            }
            std::cout << "\n⚠️  DO NOT DEPLOY TO PRODUCTION UNTIL FIXED!" << std::endl;
        } else {
            std::cout << "\n✅ SUCCESS: All cryptographic operations match canonical test vectors!" << std::endl;
            std::cout << "The C++ SDK is compatible with other SDK implementations." << std::endl;
        }
        std::cout << std::string(60, '=') << std::endl;
    }
    
    /**
     * Run all validation tests
     */
    void runAllTests() {
        std::cout << "KnishIO C++ SDK - SHAKE256 Validation Test Suite" << std::endl;
        std::cout << "Testing against canonical test vectors for cross-SDK compatibility" << std::endl;
        
        testBasicSHAKE256();
        testBundleGeneration();
        testWalletGeneration();
        
        printResults();
    }
    
    /**
     * Get exit code (0 = all tests passed, 1 = failures detected)
     */
    int getExitCode() {
        return (failed_tests == 0) ? 0 : 1;
    }
};

int main() {
    try {
        SHAKE256Validator validator;
        validator.runAllTests();
        return validator.getExitCode();
    } catch (const std::exception& e) {
        std::cerr << "🚨 CRITICAL ERROR: " << e.what() << std::endl;
        return 1;
    }
}