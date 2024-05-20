#include "../base58/base58.h"
#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"
#include <stdbool.h>

#ifndef WALLET_GEN_KEY_H
#define WALLET_GEN_KEY_H

int gen_keys(uint8_t pk[], uint8_t sk[], uint8_t seed[]);
char* encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type);
bool isPswdGood(const char *password);
char* ChooseToEncryptFile(bool HasAlreadyBeenCipher);
void sql_walletdat(uint8_t pk[], uint8_t sk[], char *userpswd, bool mustencrypt, char *finale_address);
void enc_walletdat(char *userpswd);
void dec_walletdat(char *userpswd);
void allfunctions();

#endif //WALLET_GEN_KEY_H
