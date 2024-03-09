#ifndef WALLET_WALLETDAT_AES_CPP_H
#define WALLET_WALLETDAT_AES_CPP_H


#ifdef __cplusplus
extern "C" {
#endif

void aes_file(const char *inputFilename, const char *outputFilename, const char *password);
void err(void);
void makeFileReadOnly(const char *filename);
void deriveKeyFromPassword(const char *password, unsigned char *key, unsigned char *iv);

#ifdef __cplusplus
}
#endif

#endif //WALLET_WALLETDAT_AES_CPP_H
