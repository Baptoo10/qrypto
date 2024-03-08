using namespace std;

#include "walletdat_aes_cpp.h"

#include <iostream>
#include <fstream>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string>

#define KEY_SIZE 32 // key size = 256 bits
#define IV_SIZE 16  // initialized vector size = 128 bits

void err(void){
    cerr << "Error" << endl;
    exit(1);
}

void deriveKeyFromPassword(const string &password, unsigned char *key, unsigned char *iv){
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr, reinterpret_cast<const unsigned char *>(password.c_str()), password.length(), 1, key, iv) != KEY_SIZE) {
        err();
    }
}

void aes_file(const string &inputFilename, const string &outputFilename, const string &password) {
    ifstream inputFile(inputFilename, ios::binary);
    ofstream outputFile(outputFilename, ios::binary);

    if (!inputFile || !outputFile) {
        err();
    }

    string firstLine;
    getline(inputFile, firstLine);

    cout << "first line " << firstLine << endl;

    bool crypttype;  // No need to initialize, will be false by default
    if (firstLine.find("unlock") != string::npos) {
        crypttype = true;  // la ligne contient "unlock"
    } else if (firstLine.find("lock") != string::npos) {
        crypttype = false;  // la ligne contient "lock"
    } else {
        cerr << "Invalid mode found in the file." << endl;
        exit(1);
    }

    cout << crypttype << endl;

    // Generate key and iv from password
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    deriveKeyFromPassword(password, key, iv);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (crypttype) {
        // Initialization of the cipher context
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            err();
        }
    } else {
        // Initialization of the decipher context
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            err();
        }
    }

    unsigned char buffer[1024];
    int bytesRead, cipherTextLength, plainTextLength;
    unsigned char cipherText[1024 + EVP_MAX_BLOCK_LENGTH], plainText[1024 + EVP_MAX_BLOCK_LENGTH];

    if (!crypttype) {
        // Write "lock" as the first line
        outputFile << "lock" << std::endl;
    } else if(crypttype){
        // Write "unlock" as the first line
        outputFile << "unlock" << std::endl;
    }

    while ((bytesRead = inputFile.readsome(reinterpret_cast<char *>(buffer), sizeof(buffer))) > 0) {
        if (crypttype) {
            if (EVP_EncryptUpdate(ctx, cipherText, &cipherTextLength, buffer, bytesRead) != 1) {
                err();
            }
            // Writing the ciphertext in the outputFile
            outputFile.write(reinterpret_cast<const char *>(cipherText), cipherTextLength);
        } else {
            if (EVP_DecryptUpdate(ctx, plainText, &plainTextLength, buffer, bytesRead) != 1) {
                err();
            }
            // Writing the deciphertext in the outputFile
            outputFile.write(reinterpret_cast<const char *>(plainText), plainTextLength);
        }
    }

    if (crypttype) {
        // Ending the encryption
        if (EVP_EncryptFinal_ex(ctx, cipherText, &cipherTextLength) != 1) {
            err();
        }

        // Writing the last part of the ciphertext in the outputFile
        outputFile.write(reinterpret_cast<const char *>(cipherText), cipherTextLength);

        remove(inputFilename.c_str());
    } else {
        // Ending the encryption
        if (EVP_DecryptFinal_ex(ctx, plainText, &plainTextLength) != 1) {
            err();
        }

        // Writing the last part of the deciphertext in the outputFile
        outputFile.write(reinterpret_cast<const char *>(plainText), plainTextLength);

        remove(inputFilename.c_str());
    }

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();
}

int main(int argc, char *argv[]) {
    if (argc != 4){
        cerr << "Usage: " << argv[0] << " <filename> <password> <mode: encrypt/decrypt>" << endl;
        return 1;
    }

    string inputFilename = argv[1];
    const string password = argv[2];
    const string mode = argv[3];

    if (mode != "encrypt" && mode != "decrypt") {
        cerr << "Invalid mode. Use 'encrypt' or 'decrypt'." << endl;
        return 1;
    }

    string outputFilename = (mode == "encrypt") ? "enc_" + inputFilename : inputFilename;

    aes_file(inputFilename, outputFilename, password);

    if (mode == "encrypt") {
        cout << "Encryption successful." << endl;
    } else {
        cout << "Decryption successful." << endl;
    }

    return 0;
}
