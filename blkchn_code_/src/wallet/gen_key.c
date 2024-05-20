#include "gen_key.h"
#include "config.h"

#include "../sqlite_amalgamation_3450200/sqlite3.h"
/*
 * sqlite.org :
 * "Over 100 separate source files are concatenated into a single large file of C-code named "sqlite3.c"
 * and referred to as "the amalgamation". The amalgamation contains everything an application needs to embed SQLite."
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>

#include <arpa/inet.h> // Pour la fonction htonl
#include <math.h>
#include <openssl/sha.h>

#include <openssl/ripemd.h>

#include "../avx2_dilithium3-AES-R/sign.h"

#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"

#include "../base58/base58.h"

#include "./wallet_enc_dec.h"

unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

uint8_t sk[CRYPTO_MASTERSECRETKEYBYTES];
uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t seed[3 * SEEDBYTES];

bool cipherwallet;

bool havewallet(){
    const char *dec_qptwallet = "./dec_qptwallet.dat";
    const char *encwalletdat = "./enc_qptwallet.dat";

    if (access(dec_qptwallet, F_OK) != -1) {
        printf("You already have a wallet.\n");
        cipherwallet=false;
        return true;
    }
    else if(access(encwalletdat, F_OK) != -1){
        printf("You already have a wallet (cipher one).\n");
        cipherwallet=true;
        return true;
    }
    else{
        return false;
    }
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


char* encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type) {

    char *addr_cat_crf = NULL;

    size_t b58len_crf = chainid_ripemd160_fb_len * (log(256) / log(58)) + 1;
    size_t b58len_addr = sizeof(addr_type) * (log(256) / log(58)) + 1;

    char *b58_crf = (char *)malloc(b58len_crf);
    char *b58_addr = (char *)malloc(b58len_addr);

    // Encode chainid_ripemd160_fb and addr_type
    e58(chainid_ripemd160_fb, chainid_ripemd160_fb_len, &b58_crf, &b58len_crf);
    e58(&addr_type, sizeof(addr_type), &b58_addr, &b58len_addr);

    //printf("chainid_ripemd160_fb (base58): %s\n", b58_crf);
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

    return addr_cat_crf;
}


// method to generate the address given a pk
char* gen_address(uint8_t pk[]){

    unsigned char first_bytes[4];

    // Perform first hash level with SHA256() on pk
    sha256_fun(pk, sha256_hash, 1, CRYPTO_PUBLICKEYBYTES);
    //printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    // Perform RIPEMD160 on previous sha256_hash result
    ripemd160_fun(sha256_hash, ripemd160_hash, 1);

    //printf("ripemd160_hash : %s\n", showhex(ripemd160_hash, RIPEMD160_DIGEST_LENGTH));

#ifdef MAINNET
    const uint32_t chain_id = 0x4D41494E; // hex of MAINNET => GUq8 after all in b58
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of MAINNET
#else
    const uint32_t chain_id = 0x54455354; // hex of TESTNET => HtN9K after all in b58
    const uint32_t order_chain_id = htonl(chain_id); // correct order of hex of TESTNET
#endif

//must add a b58 encode here for chain_id if we want to have MAIN and TEST in our address.

    unsigned char chainid_ripemd160[4 + RIPEMD160_DIGEST_LENGTH];
    memcpy(chainid_ripemd160, &order_chain_id, sizeof(order_chain_id));
    memcpy(chainid_ripemd160 + sizeof(order_chain_id), ripemd160_hash, RIPEMD160_DIGEST_LENGTH);
    //printf("chain_id : %08x\n", chain_id);
    //printf("chainid_ripemd160 : %s\n", showhex(chainid_ripemd160, sizeof(chainid_ripemd160)));

    //DoubleSHA256 on chainid_ripemd160
    sha256_fun(chainid_ripemd160, sha256_hash, 2, sizeof(chainid_ripemd160));
    //printf("sha256_hash : %s\n", showhex(sha256_hash, SHA256_DIGEST_LENGTH));

    //Extract 4 first bytes of the DSHA256()
    memcpy(first_bytes, sha256_hash, 4);


    //printf("Result Hash (first 4 bytes): %s\n", showhex(first_bytes, 4));

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

    //printf("chainid_ripemd160_fb : %s\n", showhex(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb)));

    char *finale_address = encodageb58(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb), addr_type);

    return finale_address;

}


/*
 * Check if the password respect the conditions
 */
bool isPswdGood(const char *password) {

    bool hasGoodLength = false;
    bool hasUpperCase = false;
    bool hasLowerCase = false;
    bool hasDigit = false;
    bool hasSpecialChar = false;

    if ((strlen(password) >= 12)&&(strlen(password) < 100)) {
        hasGoodLength = true;
    }

    for (const char *ptr = password; *ptr != '\0'; ++ptr) {
        if (isupper(*ptr)) {
            hasUpperCase = true;
        } else if (islower(*ptr)) {
            hasLowerCase = true;
        } else if (isdigit(*ptr)) {
            hasDigit = true;
        } else if (!isalnum(*ptr)) {
            hasSpecialChar = true;
        }
    }

    if (!hasGoodLength || !hasUpperCase || !hasLowerCase || !hasDigit || !hasSpecialChar) {
        fprintf(stderr, "The password is not valid. It must contain at least 12 characters, "
                        "including at least one lowercase letter, one uppercase letter, "
                        "one number, and one special character.\n\n");
        return false;
    } else {
        return true;
    }
}


// Must create a new table for tx, later (with data like 'inputtx BLOB' and 'outputtx BLOB')

/*
 * Check if the wallet is encrypted
 */
bool IsWalletEncrypted(bool enc){
    sqlite3 *db;
    int rc;

    if(enc) {
        rc = sqlite3_open("enc_qptwallet.dat", &db);
        if (rc) {
            fprintf(stderr, "Impossible to open the enc_qptwallet.dat file : %s\n", sqlite3_errmsg(db));
            return 1;
        }
    } else if (!enc){
        rc = sqlite3_open("dec_qptwallet.dat", &db);
        if (rc) {
            fprintf(stderr, "Impossible to open the dec_qptwallet.dat file : %s\n", sqlite3_errmsg(db));
            return 1;
        }
    }
    sqlite3_stmt *stmt;

    // Try to do a request to know if the file is encrypted or not
    const char *query = "SELECT * FROM qptwallet;";
    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        //fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
    // Execute the request
    rc = sqlite3_step(stmt);

    // Conclude
    if (rc == SQLITE_ROW) {
        printf("Database is not encrypted\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    } else {
        printf("Database is encrypted\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return true;
    }

}


/*
 * User chooses if he wants to encrypt his wallet or not
 */
char* ChooseToEncryptFile(bool HasAlreadyBeenCipher) {

    char* userPassword = malloc(100 * sizeof(char)); // Alloue de la mémoire pour stocker le mot de passe
    if (userPassword == NULL) {
        fprintf(stderr, "Err while allocating mem");
        exit(EXIT_FAILURE);
    }

    char userResponse;
    bool response = false;

    while (!response) {

        if(!HasAlreadyBeenCipher) {
            printf("Do you want to encrypt your wallet file with AES (recommended) ? [Y/n] ");
            scanf(" %s", &userResponse);

            if (userResponse == 'Y' || userResponse == 'y' || userResponse == 'Yes' || userResponse == 'yes' ||
                userResponse == 'YES') {
                response = true;
                printf("You have chosen to encrypt your wallet, becoming enc_qptwallet.dat file.\n");

                do {
                    printf("Choose a password (100 characters max) : ");
                    scanf(" %s", userPassword);

                    if (isPswdGood(userPassword)) {
                        return userPassword;
                    } else {
                        printf("Invalid password. Please choose another one.\n");
                    }
                } while (true);

            } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' ||
                       userResponse == 'NO') {
                response = true;
                printf("You have chosen not to encrypt your wallet, becoming dec_qptwallet.dat file.\n"
                       "If you change your mind, you can change it by typing command './gen_key_mode3'\n");

                makeFileReadOnly("dec_qptwallet.dat");

                return NULL;
            }
            else {
                printf("Invalid input. Please enter 'Y' or 'n'.\n");
            }
        }
        else{

            printf("If you want to make your wallet encrypted, please, enter your password (max 100 charac) : ");
            scanf(" %s", &userPassword);

            exit(0);
        }

    }
}



void allfunctions(){

    //If the user is setting his new qptwallet
    if(!havewallet()) {
        gen_keys(pk, sk, seed);
        char *finale_address = gen_address(pk);

        char* userPassword = ChooseToEncryptFile(false);

        if(userPassword!=NULL){
            sql_walletdat(pk, sk, userPassword, true, finale_address);
        }
        else{
            sql_walletdat(pk, sk, NULL, false, finale_address);
        }

    }

    //If the user already have a qptwallet
    else{

        // Check if the qptwallet is not encrypted
        if((!cipherwallet) && (IsWalletEncrypted(false)==false)){
            bool response = false;
            char userResponse;

            while(!response) {

                printf("\nDo you want to encrypt it ? [Y/n] ");
                scanf(" %s", &userResponse);

                if (userResponse == 'Y' || userResponse == 'y' || userResponse == 'Yes' || userResponse == 'yes' ||
                    userResponse == 'YES') {

                    response=true;

                    char* userPassword[100];

                    do {
                        printf("Choose a password (100 characters max) : ");
                        scanf(" %s", userPassword);

                        if (isPswdGood(userPassword)) {
                            enc_walletdat(userPassword);
                            break;
                        } else {
                            printf("Invalid password. Please choose another one.\n");
                        }
                    } while (true);

                } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' ||
                           userResponse == 'NO') {
                    response=true;
                    printf("You have chosen not to cipher your dec_qptwallet.dat file.\n"
                           "If you change your mind, you can change it by typing command './gen_key_mode3'\n");
                } else {
                    printf("Invalid input. Please enter 'Y' or 'n'.\n");
                }
            }

        }

        // If the qptwallet is encrypted
        else if((cipherwallet) && (IsWalletEncrypted(true)==true)){
            bool response = false;
            char userResponse;

            while(!response) {

                printf("\nDo you want to decipher it ? [Y/n] ");
                scanf(" %s", &userResponse);

                if (userResponse == 'Y' || userResponse == 'y' || userResponse == 'Yes' || userResponse == 'yes' ||
                    userResponse == 'YES') {

                    response=true;

                    char userPassword[100];

                    printf("\nPlease, enter your password (max 100 charac) : ");
                    scanf("%s", userPassword);
                    dec_walletdat(userPassword);

                } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' ||
                           userResponse == 'NO') {
                    response=true;
                    printf("You have chosen not to decipher your enc_qptwallet.dat file.\n"
                           "If you change your mind, you can change it by typing command './gen_key_mode3'\n");
                } else {
                    printf("Invalid input. Please enter 'Y' or 'n'.\n");
                }
            }
        }else{
            printf("error while reading your qptwallet file");
            exit(1);
        }

    }
}


int main(void) {

    allfunctions();

 // Tester si le hash a bien fonctionne grace au powershell windows : Get-FileHash _PATH_/pk_key | Format-List . Spoiler, ca fonctionne

    return 0;
}

