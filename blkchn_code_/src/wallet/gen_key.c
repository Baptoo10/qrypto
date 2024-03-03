#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Pour la fonction htonl

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "../avx2_dilithium3-AES-R/randombytes.h"
#include "../avx2_dilithium3-AES-R/sign.h"

#include "./base58.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

//A AJOUTER DANS UN FICHIER config.h
#define MAINNET
//#define TESTNET

#define CLASSICADDRESS


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

/*
            //S'ASSURER QUE LE HASH A BIEN FONCTIONNE :
            FILE *fPtr = fopen("./i_", "wb");
            fwrite(hash, sizeof(uint8_t), SHA256_DIGEST_LENGTH, fPtr);
            fclose(fPtr);

            //EXE LA COMMANDE :  Get-Content -Path ./i_ -Encoding Byte | ForEach-Object { '{0:X2}' -f $_ } | Out-File -FilePath ./i_hex
            //OUVRIR LE FICHIER ./i_hex et check la sortie 'SHA256(SHA256(pk))' avec le contenu du fichier
*/
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

int gen_keys(uint8_t pk[], uint8_t sk[], uint8_t seed[]) {
    // Gen of the keys (pk & sk (or mk))
    crypto_sign_keypair(pk, sk, seed);

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
    unsigned char first_bytes[4];

    // Perform first hash level with SHA256() on pk
    sha256_fun(pk, sha256_hash, 1);
    printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    // Perform RIPEMD160 on previous sha256_hash result
    ripemd160_fun(sha256_hash, ripemd160_hash, 1);

    printf("ripemd160_hash : %s\n", showhex(ripemd160_hash, RIPEMD160_DIGEST_LENGTH));

#ifdef MAINNET
    const uint32_t chain_id = 0x4D41494E; // hex of MAINNET
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of MAINNET
#else
    const uint32_t chain_id = 0x54455354; // hex of TESTNET
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of TESTNET
#endif

    unsigned char chainid_ripemd160[4 + RIPEMD160_DIGEST_LENGTH];
    memcpy(chainid_ripemd160, &order_chain_id, sizeof(order_chain_id));
    memcpy(chainid_ripemd160 + sizeof(order_chain_id), ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    printf("chain_id : %08x\n", chain_id);
    printf("chainid_ripemd160 : %s\n", showhex(chainid_ripemd160, 4 + RIPEMD160_DIGEST_LENGTH));

    //DoubleSHA256 on chainid_ripemd160
    sha256_fun(chainid_ripemd160, sha256_hash, 2);
    printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    //Extract 4 first bytes of the DSHA256()
    memcpy(first_bytes, sha256_hash, 4);

    printf("Result Hash (first 4 bytes): %s\n", showhex(first_bytes, 4));

//EWo16Wy4miGPuKkgyWTxoo5jXjY83hKyrCNTQX53Q
//Xn53KFwocJ5G6TFWSes51qfKRFHwyHdjkv4orbTmM
#ifdef CLASSICADDRESS
    //Concat of : addr_type + chainid_ripemd160 + 4 previous bytes
    const uint16_t addr_type = 0x9999; // Cq1 en b58 //pour classic version 1
    const uint16_t order_addr_type = htonl(addr_type); // correct order of hex of MAINNET

    unsigned char chainid_ripemd160_fb[sizeof(addr_type) + 4 + RIPEMD160_DIGEST_LENGTH + 4];
    memcpy(chainid_ripemd160_fb + sizeof(addr_type) + 4 + RIPEMD160_DIGEST_LENGTH, first_bytes, 4); //==aller a l'@ memoire donnee + ajouter n bytes a partir de l'emplacement
    memcpy(chainid_ripemd160_fb + sizeof(addr_type), chainid_ripemd160, 4 + RIPEMD160_DIGEST_LENGTH);

    memcpy(chainid_ripemd160_fb, &addr_type, sizeof(order_addr_type));
    printf("chainid_ripemd160_fb : %s\n", showhex(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb)));

#else
    //Concat of chainid_ripemd160 + 4 previous bytes
    unsigned char chainid_ripemd160_fb[4 + RIPEMD160_DIGEST_LENGTH + 4];
    memcpy(chainid_ripemd160_fb + 4 + RIPEMD160_DIGEST_LENGTH, first_bytes, 4); //==aller a l'@ memoire donnee + ajouter n bytes a partir de l'emplacement
    memcpy(chainid_ripemd160_fb, chainid_ripemd160, 4 + RIPEMD160_DIGEST_LENGTH);

    printf("chainid_ripemd160_fb : %s\n", showhex(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb)));
#endif

    size_t b58len = sizeof(chainid_ripemd160_fb);
    char *b58_str = (char *)malloc(b58len);

    e58(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb), &b58_str, &b58len);

    printf("chainid_ripemd160_fb (base58): %s\n", b58_str);

}

int main(void) {
    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    gen_keys(pk, mk, seed);

    // FAIRE WALLET.dat ICI avec pk + sk
    FILE *fPtr = fopen("./wallet.dat", "wb");
    fwrite(pk, sizeof(uint8_t), sizeof(pk), fPtr);
    //fwrite(pk, sizeof(uint8_t), SHA256_DIGEST_LENGTH, fPtr);
    fclose(fPtr);

    gen_address(pk);

// Tester si le hash a bien fonctionne grace au powershell windows : Get-FileHash _PATH_/pk_key | Format-List . Spoiler, ca fonctionne



    return 0;
}
