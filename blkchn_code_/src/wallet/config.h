#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdio.h>
#include <stdlib.h>


#ifndef WALLET_CONFIG_H
#define WALLET_CONFIG_H

// OS
#ifdef _WIN32 || _WIN64
    #include <Windows.h>
#elif defined(__linux__) || defined(__linux)
    #include <sys/stat.h>
#endif

// Read Only method
inline void makeFileReadOnly(const char *filename){
    #ifdef _WIN32
        SetFileAttributes(filename.c_str(), FILE_ATTRIBUTE_READONLY);
    #elif defined(__linux__) || defined(__linux)
        chmod(filename, S_IRUSR | S_IRGRP | S_IROTH);
    #endif
}

// To type shell command directly in code
inline void shell_command(char* commande){
    char full_command[200];
    sprintf(full_command, "%s > /dev/null 2>&1 &", commande);
    int result = system(full_command);

    if (result == 0) {
        printf("Command has been run successfully.\n");
    } else {
        printf("Err while executing the command.\n");
    }
}

// DILITHIUM-3-AES-CTR-R (gen_key.c)
#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32


// Address size
#define ADDRESS 44

// Network type
#define MAINNET
//#define TESTNET

// Address type
#define CLASSICADDRESS

// AES (encryptwallet.c)
#define KEY_SIZE 32 // key size = 256 bits
#define IV_SIZE 16  // initialized vector size = 128 bits

// Hash functions
extern unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
extern unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

#endif //WALLET_CONFIG_H
