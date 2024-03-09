using namespace std;

#include "walletdat_aes.h"

#ifdef _WIN32 || _WIN64
    #include <Windows.h>
#elif defined(__linux__) || defined(__linux)
    #include <sys/stat.h>
#endif

#include <iostream>
#include <fstream>
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

void makeFileReadOnly(const string &filename) {
    #ifdef _WIN32
        SetFileAttributes(filename.c_str(), FILE_ATTRIBUTE_READONLY);
    #elif defined(__linux__) || defined(__linux)
        chmod(filename.c_str(), S_IRUSR | S_IRGRP | S_IROTH);
    #endif
}

void deriveKeyFromPassword(const string &password, unsigned char *key, unsigned char *iv){
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr, reinterpret_cast<const unsigned char *>(password.c_str()), password.length(), 1, key, iv) != KEY_SIZE) {
        err();
    }
}

void aes_file(const string &inputFilename, const string &password) {

    ifstream inputFile(inputFilename, ios::binary);
    if (!inputFile) {
        err();
    }

    string firstLine;
    getline(inputFile, firstLine);
    cout << "first line " << firstLine << endl;

    string outputFilename;
    string enc = "enc_";

    bool crypttype;
    if (firstLine.find("unlock") != string::npos) {
        crypttype = true;  // Must encrypt the file
        outputFilename = enc + inputFilename;
        cout << "Encryption successful." << endl;
    }
    else if (firstLine.find("lock") != string::npos) {
        crypttype = false;  // Must descrypt the file

        size_t pos = inputFilename.find(enc);
        outputFilename = inputFilename;

        if (pos != string::npos) {
            outputFilename.erase(pos, enc.length());
            cout << "inputFilename : " << inputFilename << " | outputFilename : " << outputFilename << endl;
        }

        cout << "Decryption successful." << endl;
    }
    else {
        cerr << "Invalid mode found in the file." << endl;
        exit(1);
    }

    ofstream outputFile(outputFilename, ios::binary);

    if (!outputFile) {
        err();
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
    } else if (!crypttype){
        // Initialization of the decipher context
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
            err();
        }
    }

    unsigned char buffer[1024];
    int bytesRead, cipherTextLength, clearTextLength;
    unsigned char cipherText[1024 + EVP_MAX_BLOCK_LENGTH], clearText[1024 + EVP_MAX_BLOCK_LENGTH];

    if (crypttype) { // If the file is encrypted, must decrypt it and write "unlock" on first line
        // Write "unlock" as the first line
        outputFile << "lock" << std::endl;
    } else if(!crypttype){ // If the file is decrypted, must encrypt it and write "lock" on first line
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
        } else if(!crypttype){
            if (EVP_DecryptUpdate(ctx, clearText, &clearTextLength, buffer, bytesRead) != 1) {
                err();
            }
            // Writing the cleartext in the outputFile
            outputFile.write(reinterpret_cast<const char *>(clearText), clearTextLength);
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
    } else if(!crypttype){
        // Ending the decryption
        if (EVP_DecryptFinal_ex(ctx, clearText, &clearTextLength) != 1) {
            err();
        }

        // Writing the last part of the deciphertext in the outputFile
        outputFile.write(reinterpret_cast<const char *>(clearText), clearTextLength);

        remove(inputFilename.c_str());
    }

    //NE FONCTIONNE PAS jsp pk
    makeFileReadOnly(outputFilename);

    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

}

int main(int argc, char *argv[]) {

    if (argc != 3){
        cerr << "Usage: " << argv[0] << " <filename> <password>" << endl;
        return 1;
    }

    string inputFilename = argv[1];
    const string password = argv[2];

    aes_file(inputFilename, password);

    return 0;
}
