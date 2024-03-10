#ifndef WALLET_WAL_H
#define WALLET_WAL_H

void errFile(const char *errmessage, const char *filename);
void err(void);
void deriveKeyFromPassword(const char *password, unsigned char *key, unsigned char *iv);
void aes_file(const char *inputFilename, const char *password);

#endif //WALLET_WAL_H
