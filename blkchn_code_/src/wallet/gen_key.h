#include <cstdint>
#include "HashFunction/RIPEMD160/ripemd160.h"
#include "HashFunction/SHA256/sha256.h"

#ifndef WALLET_GEN_KEY_H
#define WALLET_GEN_KEY_H


char *showhex(uint8_t a[], int size);

int gen_keys(uint8_t pk, uint8_t mk, uint8_t seed);

#endif //WALLET_GEN_KEY_H
