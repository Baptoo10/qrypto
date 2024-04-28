#include "sha256_file.h"

#include <stdint.h>
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <ostream>
#include <vector>

using namespace std;

int sha256_file_fun(const char* filename, unsigned char *hash, int rounds) {

    ifstream file(filename, ios::binary | ios::ate);
    if (!file.is_open()) {
        cerr << "Err opening the file: " << filename << endl;
        return -1;
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<uint8_t> buffer(size);
    
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        cerr << "Err reading the file: " << filename << endl;
        return -1;
    }
    file.close();

    // hash n times
    for (int i = 0; i < rounds; ++i) {

        // create sha256 context
        SHA256_CTX sha256_ctx;

        // sha256 op
        SHA256_Init(&sha256_ctx);
        SHA256_Update(&sha256_ctx, buffer.data(), size);
        SHA256_Final(hash, &sha256_ctx);

        // hash is now the new data for next round
        copy(hash, hash + SHA256_DIGEST_LENGTH, buffer.begin());
    }

    return 0;
}