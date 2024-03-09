//REGARDER INMPLEMENTATION walletdat_aes.cpp dans gen_key.c sans le main peutêtre


#ifndef WALLET_CONFIG_H
#define WALLET_CONFIG_H

#ifdef _WIN32 || _WIN64
    #include <Windows.h>
#elif defined(__linux__) || defined(__linux)
    #include <sys/stat.h>
#endif

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


#endif //WALLET_CONFIG_H
