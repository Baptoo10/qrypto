#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

char *showhex(const uint8_t a[], int size);

char *showhex(const uint8_t a[], int size) {
    char *s = (char *)malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return s;
}

int gen_keys(uint8_t pk[], uint8_t mk[], uint8_t seed[]) {
    // Gen of the keys (pk & sk (or mk))
    crypto_sign_keypair(pk, mk, seed);

    printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    //printf("CRYPTO_MASTERSECRETKEYBYTES = %d\n", CRYPTO_MASTERSECRETKEYBYTES);
    //printf("SEEDBYTES = %d\n", 3 * SEEDBYTES);

    printf("\nClé publique : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    //printf("\nClé privée : %s\n", showhex(mk, CRYPTO_MASTERSECRETKEYBYTES));
    //printf("\nSeed : %s\n", showhex(seed, 3 * SEEDBYTES));

    return 0;
}


int sha256_fun(uint8_t pk[], unsigned char *hash) {
    // Definition de la structure de donnees SHA256_CTX afin de stocker
    // des etats intermediaires internes pendant le processus de calcul du hachage.
    SHA256_CTX sha256_ctx;
    // Initialisation d'une valeur de hash H^(0) initiale
    SHA256_Init(&sha256_ctx);
    // Calcul incrementiel du hash du message en fragments
    SHA256_Update(&sha256_ctx, pk, CRYPTO_PUBLICKEYBYTES);
    // Calcul du hash final après que tous les fragments aient été hashés avec SHA256_Update
    SHA256_Final(hash, &sha256_ctx);

    return 0;
}
void print_binary(const uint8_t a[], int size);

int main(void) {
    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

    gen_keys(pk, mk, seed);

    sha256_fun("oui", sha256_hash);

    // FAIRE WALLET.dat ICI
    FILE *fPtr = fopen("./pk_key", "wb"); // Utilisez "wb" pour écrire en mode binaire
    fwrite(pk, sizeof(uint8_t), CRYPTO_PUBLICKEYBYTES, fPtr);
    fclose(fPtr);

    // OBJECTIF MAINTENANT : S'ASSURER QUE SHA256 fonctionne (normalement oui)
    printf("\nInput String: %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    printf("Binary Public Key:\n");
    print_binary(pk, CRYPTO_PUBLICKEYBYTES);
    printf("\n");

    printf("\nSHA-256 Hash: ");

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", sha256_hash[i]);
    }
    printf("\n");

    return 0;
}
void print_binary(const uint8_t a[], int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (a[i] >> j) & 1);
        }
    }
    printf("\n");
}
int address(){

}