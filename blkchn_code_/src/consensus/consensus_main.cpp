#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <stdbool.h>
#include <openssl/sha.h>
#include <cstdio>
#include "../HashFunctions/SHA256/sha256_file.h"

using namespace std;

const int rounds = 10000000; //must calc the exact nb of rounds depending smthing
unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

int run_hashrounds(){
    const char* filename = "./Makefile";

    if (sha256_file_fun(filename, sha256_hash, rounds) == 0) {

        cout << "Hash of the block : ";
        for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
            cout << hex << static_cast<int>(sha256_hash[i]);
        }
        cout << endl;
    } else {
        cerr << "Error in the sha256 calcul of the block" << endl;
    }
}

int main() {

    run_hashrounds();

    return 0;
}