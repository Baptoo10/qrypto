#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_SECRETKEYBYTES 4016

char *showhex(uint8_t a[], int size);

char *showhex(uint8_t a[], int size) {
    char *s = (char *)malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return s;
}

int main(void) {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];

    // Génération de la paire de clés
    crypto_sign_keypair(pk, sk);

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    printf("CRYPTO_SECRETKEYBYTES = %d\n", CRYPTO_SECRETKEYBYTES);

    printf("\nClé publique : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    printf("\nClé privée : %s\n", showhex(sk, CRYPTO_SECRETKEYBYTES));

    return 0;
}
