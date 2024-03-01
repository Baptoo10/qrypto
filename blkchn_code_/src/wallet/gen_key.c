#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

//A AJOUTER DANS UN FICHIER config.h
#define MAINNET
//#define TESTNET


char *showhex(const uint8_t a[], int size);
void print_binary(const uint8_t a[], int size);

char *showhex(const uint8_t a[], int size) {
    char *s = (char *)malloc(size * 2 + 1);

    for (int i = 0; i < size; i++)
        sprintf(s + i * 2, "%02x", a[i]);

    return s;
}

void print_binary(const uint8_t a[], int size) {
    for (int i = 0; i < size; i++) {
        for (int j = 7; j >= 0; j--) {
            printf("%d", (a[i] >> j) & 1);
        }
    }
    printf("\n");
}

int ripemd160_fun(uint8_t data[], unsigned char *hash, uint8_t rounds) {

    for (int i = 0; i < rounds; ++i) {

        RIPEMD160_CTX ripemd160_ctx;
        // Initialisation d'une valeur de hash
        RIPEMD160_Init(&ripemd160_ctx);
        // Calcul incrementiel du hash du message en fragments
        RIPEMD160_Update(&ripemd160_ctx, data, RIPEMD160_DIGEST_LENGTH);
        // Calcul du hash final après que tous les fragments aient été hashés avec RIPEMD160_Update
        RIPEMD160_Final(hash, &ripemd160_ctx);

        data = hash;
    }
    return 0;
}

int sha256_fun(uint8_t data[], unsigned char *hash, uint8_t rounds) {

    for (int i = 0; i < rounds; ++i) {
        // Definition de la structure de donnees SHA256_CTX afin de stocker
        // des etats intermediaires internes pendant le processus de calcul du hachage.
        SHA256_CTX sha256_ctx;
        // Initialisation d'une valeur de hash H^(0) initiale
        SHA256_Init(&sha256_ctx);

        if(data==hash){
            // Calcul incrementiel du hash du message en fragments
            SHA256_Update(&sha256_ctx, data, SHA256_DIGEST_LENGTH);
            printf("pk==hash");
            // Calcul du hash final après que tous les fragments aient été hashés avec SHA256_Update
            SHA256_Final(hash, &sha256_ctx);

            //S'ASSURER QUE LE HASH A BIEN FONCTIONNE :
            FILE *fPtr = fopen("./i_", "wb");
            fwrite(hash, sizeof(uint8_t), SHA256_DIGEST_LENGTH, fPtr);
            fclose(fPtr);

            //EXE LA COMMANDE :  Get-Content -Path ./i_ -Encoding Byte | ForEach-Object { '{0:X2}' -f $_ } | Out-File -FilePath ./i_hex
            //OUVRIR LE FICHIER ./i_hex et check la sortie 'SHA256(SHA256(pk))' avec le contenu du fichier
        }else{
            // Calcul incrementiel du hash du message en fragments
            SHA256_Update(&sha256_ctx, data, CRYPTO_PUBLICKEYBYTES);
            // Calcul du hash final après que tous les fragments aient été hashés avec SHA256_Update
            SHA256_Final(hash, &sha256_ctx);
        }

        data = hash;
    }

    return 0;
}

int gen_keys(uint8_t pk[], uint8_t mk[], uint8_t seed[]) {
    // Gen of the keys (pk & sk (or mk))
    crypto_sign_keypair(pk, mk, seed);

    //printf("CRYPTO_PUBLICKEYBYTES = %d\n", CRYPTO_PUBLICKEYBYTES);
    //printf("CRYPTO_MASTERSECRETKEYBYTES = %d\n", CRYPTO_MASTERSECRETKEYBYTES);
    //printf("SEEDBYTES = %d\n", 3 * SEEDBYTES);

    //printf("\nClé publique : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    //printf("\nClé privée : %s\n", showhex(mk, CRYPTO_MASTERSECRETKEYBYTES));
    //printf("\nSeed : %s\n", showhex(seed, 3 * SEEDBYTES));

    return 0;
}

int gen_address(uint8_t pk[]){

    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

    ///////////////////
    unsigned char *pk_to_sha256_1 = sha256_fun(pk, sha256_hash, 1);

    printf("\nSHA256(SHA256(pk)) : ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", sha256_hash[i]);
    }
    printf("\n");

    unsigned char *sha256_1_to_ripemd160 = ripemd160_fun(&pk_to_sha256_1, ripemd160_hash, 1);


    //REVIEW A PARTIR D'ICI | Suivre les instructions de construction d'@ ici : https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
#ifdef MAINNET
    char chain_id[7] = "4D41494E4E4554"; //hex of MAINNET
#else
    char chain_id[7] = "544553544E4554"; //hex of TESTNET
#endif

    // Concatenate chain ID and RIPEMD160 hash
    unsigned char *chainid_ripemd160 = strcat(chain_id, &sha256_1_to_ripemd160);

    unsigned char *chainid_ripemd160_to_dsha256 = sha256_fun(&chainid_ripemd160, sha256_hash, 2);
    // Extract the first 4 bytes
    unsigned char final_hash[4];
    memcpy(result, final_hash, 4);

    unsigned char *final_hash = strcat(&chainid_ripemd160, &chainid_ripemd160_to_dsha256);

    /*
    unsigned char pk_ripemd160 = ripemd160_fun(&pk_sha256, ripemd160_hash);
    printf("\nripemd160_hash Hash: ");

    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        printf("%02x", ripemd160_hash[i]);
    }
    printf("\n");
*/


}

int main(void) {
    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    gen_keys(pk, mk, seed);

    // FAIRE WALLET.dat ICI avec pk + sk
    FILE *fPtr = fopen("./wallet.dat", "wb");
    fwrite(pk, sizeof(uint8_t), SHA256_DIGEST_LENGTH, fPtr);
    fclose(fPtr);

    gen_address(pk);

// Tester si le hash a bien fonctionne grace au powershell windows : Get-FileHash _PATH_/pk_key | Format-List . Spoiler, ca fonctionne



    return 0;
}
