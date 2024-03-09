using namespace std;

#ifndef WALLET_WALLETDAT_AES_CPP_H
#define WALLET_WALLETDAT_AES_CPP_H

#include <string>

void aes_file(const string &inputFilename, const string &outputFilename, const string &password);
void err(void);
void makeFileReadOnly(const string &filename);
void deriveKeyFromPassword(const string &password, unsigned char *key, unsigned char *iv);


#endif //WALLET_WALLETDAT_AES_CPP_H
