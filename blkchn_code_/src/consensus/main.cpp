#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <stdbool.h>
#include <openssl/sha.h>
#include <cstdio>
#include "../HashFunctions/SHA256/sha256.h"
unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
int num_rounds = 64;
int num_threads = 4;

using namespace std;


//done
vector<int> leader(int timestamp){
    uint8_t data[sizeof(timestamp)];
    vector<int> H;
    // compute k times n/k hash, so n hash is calculated
    for(int i=0; i<num_threads; ++i){
        int hash = sha256_fun(data, sha256_hash, num_rounds/num_threads, sizeof(data)-1);
        uint8_t data[sizeof(hash)];
        H.push_back(hash);
    }

    return H; //return vector of hash, and the last one determine the next leader
}

// from chatGPT
bool verify_hashes(int timestamp, const vector<int>& hashes) {
    // Divide the hashes into k segments
    int segment_size = num_rounds / num_threads;

    // Verify each segment in parallel
    vector<thread> threads;
    bool all_hashes_correct = true;
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([i, timestamp, segment_size, &hashes, &all_hashes_correct]() {
            int start = i * segment_size;
            int end = (i + 1) * segment_size;

            // Compute the hash for the beginning of the segment
            int expected_hash = leader(timestamp)[i];

            // Verify each hash in the segment
            for (int j = start; j < end; ++j) {
                int hash = hashes[j];
                if (hash != expected_hash) {
                    all_hashes_correct = false;
                    break;
                }
                // Update expected hash for the next iteration
                expected_hash = sha256_fun((uint8_t*)&expected_hash, sha256_hash, 1, sizeof(expected_hash));
            }
        });
    }

    // Join all threads
    for (auto& t : threads) {
        t.join();
    }

    return all_hashes_correct;
}

int main() {
    const int timestamp = 10; // for instance

    // Step 1: Compute hashes
    vector<int> hashes = leader(timestamp);

    // Step 2: Verify hashes
    bool verified = verify_hashes(timestamp, hashes);
    if (verified) {
        cout << "All hashes are correct." << endl;
    } else {
        cout << "Some hashes are incorrect." << endl;
    }

    return 0;
}//
// Created by user on 11/04/2024.
//

//* #include <iostream>
//#include <vector>
//#include <thread>
//
//using namespace std;
//
//// Simulated sha256 function
//int sha256_fun(uint8_t data[], unsigned char *hash, int rounds, size_t data_len) {
//    // Simulated hash calculation, replace with actual implementation
//    return data_len * rounds; // Dummy return value
//}
//
//vector<int> leader(int horodatage, int k, int N) {
//    vector<int> H;
//    int data = horodatage;
//
//    // Compute k times n/k hash, so n hash is calculated
//    for (int i = 0; i < k; ++i) {
//        int hash = sha256_fun((uint8_t*)&data, nullptr, N/k, sizeof(data));
//        data = hash;
//        H.push_back(hash);
//    }
//
//    return H; // Return vector of hash, and the last one determine the next leader
//}
//
//bool verify_hashes(int horodatage, int k, int N, const vector<int>& hashes) {
//    // Divide the hashes into k segments
//    int segment_size = N / k;
//
//    // Verify each segment in parallel
//    vector<thread> threads;
//    bool all_hashes_correct = true;
//    for (int i = 0; i < k; ++i) {
//        threads.emplace_back([i, horodatage, segment_size, &hashes, &all_hashes_correct]() {
//            int start = i * segment_size;
//            int end = (i + 1) * segment_size;
//
//            // Compute the hash for the beginning of the segment
//            int expected_hash = leader(horodatage, k, N)[i];
//
//            // Verify each hash in the segment
//            for (int j = start; j < end; ++j) {
//                int hash = hashes[j];
//                if (hash != expected_hash) {
//                    all_hashes_correct = false;
//                    break;
//                }
//                // Update expected hash for the next iteration
//                expected_hash = sha256_fun((uint8_t*)&expected_hash, nullptr, 1, sizeof(expected_hash));
//            }
//        });
//    }
//
//    // Join all threads
//    for (auto& t : threads) {
//        t.join();
//    }
//
//    return all_hashes_correct;
//}
//
//int main() {
//    int horodatage = 123; // Example timestamp
//    int k = 4; // Number of segments
//    int N = 16; // Total number of rounds
//
//    // Step 1: Compute hashes
//    vector<int> hashes = leader(horodatage, k, N);
//
//    // Step 2: Verify hashes
//    bool verified = verify_hashes(horodatage, k, N, hashes);
//    if (verified) {
//        cout << "All hashes are correct." << endl;
//    } else {
//        cout << "Some hashes are incorrect." << endl;
//    }
//
//    return 0;
//}