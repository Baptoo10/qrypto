#include "sha256_file.h"

#include <stdint.h>
#include <openssl/sha.h>
#include <fstream>
#include <iostream>
#include <ostream>
#include <vector>

#include "../../print_type/printtype.h"

using namespace std;

int sha256_file_fun(const char* filename_or_data, unsigned char *hash, int rounds, bool isDataIsFile) {

    if (isDataIsFile) {
        // ios::ate places the cursor at the end of the file => allows you to know the size of the file with .tellg()
        ifstream file(filename_or_data, ios::binary | ios::ate);
        if (!file.is_open()) {
            cerr << "Err opening the file: " << filename_or_data << endl;
            return 1;
        }

        streamsize size = file.tellg();
        file.seekg(0, ios::beg); //ios::beg = beginning of file

        vector<uint8_t> buffer(size);

        if (!file.read(reinterpret_cast<char *>(buffer.data()), size)) {
            cerr << "Err reading the file: " << filename_or_data << endl;
            return 1;
        }
        file.close();

        // hash n (or rounds) times
        for (int i = 0; i < rounds; ++i) {

            // create sha256 context
            SHA256_CTX sha256_ctx;

            // sha256 op
            SHA256_Init(&sha256_ctx);
            if(i==0)
                SHA256_Update(&sha256_ctx, buffer.data(), size);
            else
                SHA256_Update(&sha256_ctx, hash, SHA256_DIGEST_LENGTH);
            SHA256_Final(hash, &sha256_ctx);

            // hash is now the new data for next round | copy() is faster than memcpy()
            copy(hash, hash + SHA256_DIGEST_LENGTH, buffer.begin());

        }

        return 0;

    }
    else {
        // hash n (or rounds) times
        for (int i = 0; i < rounds; ++i) {

            /*
            cout << "Bin hash of the previous hash : ";
            print_binary(reinterpret_cast<const uint8_t *>(filename_or_data), SHA256_DIGEST_LENGTH);
            cout << endl;
            */
            /*
            if(i==0) {
                char *hex_string = showhex(reinterpret_cast<const uint8_t *>(filename_or_data), SHA256_DIGEST_LENGTH);
                cout << "Hex hash of the prev file : " << hex_string << endl;
                cout << "bonjour" << i << endl;
            }
            else{
                char *hex_string = showhex(reinterpret_cast<const uint8_t *>(hash), SHA256_DIGEST_LENGTH);
                cout << "Hex hash of the prev file : " << hex_string << endl;
                cout << "bonjour" << i << endl;
            }
            */

            // create sha256 context
            SHA256_CTX sha256_ctx;

            // sha256 op
            SHA256_Init(&sha256_ctx);
            if(i==0)
                SHA256_Update(&sha256_ctx, filename_or_data, SHA256_DIGEST_LENGTH);
            else
                SHA256_Update(&sha256_ctx, hash, SHA256_DIGEST_LENGTH);

            SHA256_Final(hash, &sha256_ctx);

            // hash is now the new data for next round | copy() is faster than memcpy()
            copy(hash, hash + SHA256_DIGEST_LENGTH, hash); // Copy hash into hash itself

        }

        return 0;

    }
}