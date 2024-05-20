#ifndef WALLET_WALLET_ENC_DEC_H
#define WALLET_WALLET_ENC_DEC_H

#include <stdint.h>
#include <stdbool.h>

void sql_walletdat(uint8_t pk[], uint8_t sk[], char *userpswd, bool mustencrypt, char *finale_address);
void enc_walletdat(char *userpswd);
void dec_walletdat(char *userpswd);

#endif //WALLET_WALLET_ENC_DEC_H
