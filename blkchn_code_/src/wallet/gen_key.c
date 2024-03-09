#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h> // Pour la fonction htonl
#include <math.h>
#include <stdbool.h>
#include <regex.h>

#include <openssl/sha.h>
#include <openssl/ripemd.h>

#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"

#include "../avx2_dilithium3-AES-R/sign.h"

#include "../base58/base58.h"

#define CRYPTO_PUBLICKEYBYTES 1952
#define CRYPTO_MASTERSECRETKEYBYTES 4016
#define SEEDBYTES 32

#define ADDRESS 44

//A AJOUTER DANS UN FICHIER config.h
#define MAINNET
//#define TESTNET

#define CLASSICADDRESS

char *addr_cat_crf = NULL;

char *showhex(const uint8_t a[], int size);
void print_binary(const uint8_t a[], int size);
int gen_keys(uint8_t pk[], uint8_t sk[], uint8_t seed[]);
void encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type);
bool isPswdGood_regex(const char *password);


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


void encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type) {

    size_t b58len_crf = chainid_ripemd160_fb_len * (log(256) / log(58)) + 1;
    size_t b58len_addr = sizeof(addr_type) * (log(256) / log(58)) + 1;

    char *b58_crf = (char *)malloc(b58len_crf);
    char *b58_addr = (char *)malloc(b58len_addr);

    // Encode chainid_ripemd160_fb and addr_type
    e58(chainid_ripemd160_fb, chainid_ripemd160_fb_len, &b58_crf, &b58len_crf);
    e58(&addr_type, sizeof(addr_type), &b58_addr, &b58len_addr);

    printf("chainid_ripemd160_fb (base58): %s\n", b58_crf);
    //printf("b58_addr (base58): %s\n", b58_addr);

    // Allocate memory for addr_cat_crf
    addr_cat_crf = (char *)malloc(b58len_crf + b58len_addr + 1);

    // Check for memory allocation success
    if (addr_cat_crf == NULL) {
        fprintf(stderr, "Error: Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    // Combine b58_addr and b58_crf into addr_cat_crf
    strcpy(addr_cat_crf, b58_addr);
    strcat(addr_cat_crf, b58_crf);

    printf("ADDRESS : b58_addr||chainid_ripemd160_fb (base58): %s\n", addr_cat_crf);

    // Free memory
    free(b58_crf);
    free(b58_addr);
}


// method to generate the address given a pk
int gen_address(uint8_t pk[]){
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    unsigned char first_bytes[4];

    // Perform first hash level with SHA256() on pk
    sha256_fun(pk, sha256_hash, 1, CRYPTO_PUBLICKEYBYTES);
    //printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    // Perform RIPEMD160 on previous sha256_hash result
    ripemd160_fun(sha256_hash, ripemd160_hash, 1);

    //printf("ripemd160_hash : %s\n", showhex(ripemd160_hash, RIPEMD160_DIGEST_LENGTH));

#ifdef MAINNET
    const uint32_t chain_id = 0x4D41494E; // hex of MAINNET
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of MAINNET
#else
    const uint32_t chain_id = 0x54455354; // hex of TESTNET => HtN9K in b58
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of TESTNET => GUq8 in b58
#endif

    unsigned char chainid_ripemd160[4 + RIPEMD160_DIGEST_LENGTH];
    memcpy(chainid_ripemd160, &order_chain_id, sizeof(order_chain_id));
    memcpy(chainid_ripemd160 + sizeof(order_chain_id), ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    //printf("chain_id : %08x\n", chain_id);
    printf("chainid_ripemd160 : %s\n", showhex(chainid_ripemd160, sizeof(chainid_ripemd160)));

    //DoubleSHA256 on chainid_ripemd160
    sha256_fun(chainid_ripemd160, sha256_hash, 2, sizeof(chainid_ripemd160));
    //printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    //Extract 4 first bytes of the DSHA256()
    memcpy(first_bytes, sha256_hash, 4);

    printf("Result Hash (first 4 bytes): %s\n", showhex(first_bytes, 4));


#ifdef CLASSICADDRESS
    const uint16_t addr_type = 0x6C9B; // Cq1 en b58 //pour classic version 1
#else
    const uint16_t addr_type = 0x0000; // 11 en b58 //pour default
#endif

    //Concat of : addr_type + chainid_ripemd160 + 4 previous bytes
    const uint16_t order_addr_type = htonl(addr_type); // correct order of hex of MAINNET


    unsigned char chainid_ripemd160_fb[sizeof(addr_type) + 4 + RIPEMD160_DIGEST_LENGTH + 4];
    memcpy(chainid_ripemd160_fb + sizeof(addr_type) + 4 + RIPEMD160_DIGEST_LENGTH, first_bytes, 4);
    memcpy(chainid_ripemd160_fb, chainid_ripemd160, 4 + RIPEMD160_DIGEST_LENGTH);

    printf("chainid_ripemd160_fb : %s\n", showhex(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb)));

    encodageb58(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb), addr_type);


}

void walletdat(uint8_t pk[], uint8_t sk[]) {

    FILE *fPtr = fopen("./wallet.dat", "wb");

    if (fPtr == NULL) {
        printf(stderr, "Error: Cannot open the wallet.dat file for writing (wb).\n");
        exit(1);
    }

    // State of the file
    fprintf(fPtr, "unlock\n");

    // Writing bruts values
    fprintf(fPtr, "brut values : \n");

    fprintf(fPtr, "brut public key :\n");
    fwrite(pk, sizeof(uint8_t), CRYPTO_PUBLICKEYBYTES, fPtr);

    fprintf(fPtr, "\n\nbrut secret key :\n");
    fwrite(sk, sizeof(uint8_t), CRYPTO_SECRETKEYBYTES, fPtr);

    //////////////////////////////////////////////////////////////////////

    // Écriture des valeurs hexadécimales
    fprintf(fPtr, "\n\nhex values : \n");

    fprintf(fPtr, "public key : %s\n", showhex(pk, CRYPTO_PUBLICKEYBYTES));
    fprintf(fPtr, "secret key : %s\n", showhex(sk, CRYPTO_SECRETKEYBYTES));
    fprintf(fPtr, "address : %s\n", addr_cat_crf);

    fclose(fPtr);

    // Free memory
    free(addr_cat_crf);
}

void encryptfile(){
    char userResponse;
    bool response = false;

    while (!response) {
        printf("Do you want to encrypt your wallet file with AES (recommended) ? [Y/n] ");
        scanf(" %c", &userResponse);

        if (userResponse == 'Y' || userResponse == 'y' || userResponse == 'Yes' || userResponse == 'yes' || userResponse == 'YES'){
            response = true;
            printf("You have chosen to encrypt the wallet.dat file.\n");

            char userPassword[100];

            do {
                printf("Choose a password (100 characters max) : ");
                scanf(" %s", &userPassword);

            } while (!isPswdGood_regex(userPassword));


            char command[130];
            sprintf(command, "./walletdat_aes wallet.dat %s", userPassword);

            int result = system(command);

            if (result == 0) {
                printf("La commande a été exécutée avec succès.\n");
            } else {
                printf("Erreur lors de l'exécution de la commande.\n");
            }


        } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' || userResponse == 'NO'){
            response = true;
            printf("You have chosen not to encrypt the wallet.dat file.\n"
                   "If you change your mind, you can change it by typing command 'encryptwallet'\n");
        }
        else {
            printf("Invalid input. Please enter 'Y' or 'n'.\n");
        }
    }

}


bool isPswdGood_regex(const char *password) {
    regex_t regex;
    int returncode;
    char errorbuf[100];

    const char *pattern = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[\\W_]).{12,}$";

    returncode = regcomp(&regex, &pattern, REG_EXTENDED); // Utilisation de la variable pattern ici

    if (returncode) {
        regerror(returncode, &regex, errorbuf, sizeof(errorbuf));
        fprintf(stderr, "Could not compile regex: %s\n", errorbuf);
        exit(1);
    }

    returncode = regexec(&regex, password, 0, NULL, 0); // Utilisation de la variable password ici

    if (!returncode) {
        printf("The password is valid.\n");
        regfree(&regex);
        return true; // La regex correspond au mot de passe
    }
    else if (returncode == REG_NOMATCH) {
        printf("The password is not valid. It must contain at least 12 characters, including at least one"
               " lowercase letter, one uppercase letter, one number, and one special character.\n\n");
        regfree(&regex);
        return false; // La regex ne correspond pas au mot de passe
    }
    else {
        regerror(returncode, &regex, errorbuf, sizeof(errorbuf));
        fprintf(stderr, "Regex match failed: %s\n", errorbuf);
        exit(1);
    }
}



int main(void) {
    uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t seed[3 * SEEDBYTES];

    gen_keys(pk, mk, seed);
    gen_address(pk);

/*
 * PAS UTILE POUR LE MOMENT MAIS PEUT ETRE POUR LES TX
PENSER A AJOUTER #include walletdatconfig.h OU walletdat_encrypt.h et walletdat_decrypt pour savoir si oui ou non le wallet est unlock
#ifdef WALLETUNLOCK
    #undef WALLETLOCK
*/
    walletdat(pk, mk);
    encryptfile();

// Tester si le hash a bien fonctionne grace au powershell windows : Get-FileHash _PATH_/pk_key | Format-List . Spoiler, ca fonctionne

    return 0;
}


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