#ifndef API_H
#define API_H

#include "config.h"

#if DILITHIUM_MODE == 3
#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_SECRETKEYBYTES 4016
#define CRYPTO_BYTES 3293
#endif

#define crypto_sign_keypair DILITHIUM_NAMESPACE(_keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign DILITHIUM_NAMESPACE()
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *msg, unsigned long long len,
                const unsigned char *sk);

// Alias pour la fonction en conflit
#define pqcrystals_dilithium3aes_r_avx2_open_alias pqcrystals_dilithium3aes_r_avx2_open
int pqcrystals_dilithium3aes_r_avx2_open_alias(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
/*
#ifndef API_H
#define API_H

#include "config.h"

#if DILITHIUM_MODE == 3
#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_SECRETKEYBYTES 4016
#define CRYPTO_BYTES 3293
#endif

#define crypto_sign_keypair DILITHIUM_NAMESPACE(_keypair)
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_sign DILITHIUM_NAMESPACE()
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *msg, unsigned long long len,
                const unsigned char *sk);

#define crypto_sign_open DILITHIUM_NAMESPACE(_open)
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk);

#endif
*/

