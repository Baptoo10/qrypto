#include <cstdint>

#ifndef WALLET_GEN_KEY_H
#define WALLET_GEN_KEY_H


char *showhex(uint8_t a[], int size);

int gen_keys(uint8_t pk, uint8_t mk, uint8_t seed);

#endif //WALLET_GEN_KEY_H
