#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"
#include "HashFunction/SHA256/sha256.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

char *showhex(const uint8_t a[], int size);

int gen_keys(uint8_t pk[], uint8_t mk[], uint8_t seed[]) {
    // Gen of the keys (pk & sk (or mk))
    crypto_sign_keypair(pk, mk, seed);

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_MASTERSECRETKEYBYTES = %d\n", CRYPTO_MASTERSECRETKEYBYTES);
    printf("SEEDBYTES = %d\n", 3 * SEEDBYTES);

    printf("\nClé publique : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    printf("\nClé privée : %s\n", showhex(mk, CRYPTO_MASTERSECRETKEYBYTES));
    printf("\nSeed : %s\n", showhex(seed, 3 * SEEDBYTES));

    return 0;
}

int sha256_fun(const uint8_t pk[]) {
    SHA256_CTX ctx;
    BYTE hash[SHA256_BLOCK_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, pk, CRYPTO_PUBLICKEYBYTES);
    sha256_final(&ctx, hash);

    printf("\n\nSHA-256 Hash: ");
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return 0;
}

int main(void) {
    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    gen_keys(pk, mk, seed);

    sha256_fun(pk);

    return 0;
}

char *showhex(const uint8_t a[], int size) {
    char *s = (char *)malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return s;
}


/*
 * #include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

char *showhex(uint8_t a[], int size);
int address();
char *showhex(uint8_t a[], int size) {
    char *s = (char *)malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return s;
}

int main(void) {

    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    // Génération de la paire de clés
    crypto_mk_seed(pk, mk, seed);

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_MASTERSECRETKEYBYTES = %d\n", CRYPTO_MASTERSECRETKEYBYTES);
    printf("SEEDBYTES = %d\n", 3 * SEEDBYTES);

    printf("\nClé publique : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    printf("\nClé privée : %s\n", showhex(mk, CRYPTO_MASTERSECRETKEYBYTES));
    printf("\nSeed : %s\n", showhex(seed, 3 * SEEDBYTES));

    return 0;
}


int address(){

}

 */