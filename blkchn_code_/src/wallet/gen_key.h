#include <cstdint>

#include "../base58/base58.h"
#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"

#ifndef WALLET_GEN_KEY_H
#define WALLET_GEN_KEY_H


char *showhex(uint8_t a[], int size);

int gen_keys(uint8_t pk, uint8_t mk, uint8_t seed);

#endif //WALLET_GEN_KEY_H
