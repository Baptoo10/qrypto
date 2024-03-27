#include "config.h"
//#include "leveldb/c.h"
#include <sqlite3.h>
//#include "../sqlite_amalgamation_3450200/sqlite3.h"
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

#include <arpa/inet.h> // Pour la fonction htonl
#include <math.h>
#include <openssl/sha.h>

#include <openssl/ripemd.h>

#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"

#include "../avx2_dilithium3-AES-R/sign.h"

#include "../base58/base58.h"

#include "../print_type/printtype.h"

#include "encryptwallet.h"
#include "walletdat_aes.h"

uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t seed[3 * SEEDBYTES];

unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];

char *addr_cat_crf = NULL;

bool cipherwallet;


int gen_keys(uint8_t pk[], uint8_t sk[], uint8_t seed[]);
void encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type);
void allfunctions();

bool havewallet(){
    const char *walletdat = "./wallet.dat";
    const char *encwalletdat = "./enc_wallet.dat";

    if (access(walletdat, F_OK) != -1) {
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


void encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type) {

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
}


// method to generate the address given a pk
int gen_address(uint8_t pk[]){

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

    encodageb58(chainid_ripemd160_fb, sizeof(chainid_ripemd160_fb), addr_type);


}

void walletdat(uint8_t pk[], uint8_t sk[]){
    sqlite3 *db;

// Ouvrir la base de données SQLite
    int rc = sqlite3_open("wallet.dat", &db);
    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

// Créer la table si elle n'existe pas déjà
    char *sql = "CREATE TABLE IF NOT EXISTS wallet (public_key TEXT, secret_key TEXT, address TEXT);";
    rc = sqlite3_exec(db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

// Préparer la requête d'insertion
    sql = "INSERT INTO wallet (public_key, secret_key, address) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't prepare statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

// Binder les valeurs et exécuter la requête
    rc = sqlite3_bind_text(stmt, 1, showhex(pk, CRYPTO_PUBLICKEYBYTES), -1, SQLITE_STATIC);
    rc = sqlite3_bind_text(stmt, 2, showhex(sk, CRYPTO_SECRETKEYBYTES), -1, SQLITE_STATIC);
    rc = sqlite3_bind_text(stmt, 3, addr_cat_crf, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Can't execute statement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }

// Finaliser et fermer la base de données
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

/*
void walletdat(uint8_t pk[], uint8_t sk[]) {

    FILE *fPtr = fopen("./wallet.dat", "wb");

    if (fPtr == NULL) {
        printf(stderr, "Error: Cannot open the wallet.dat file for writing (wb).\n");
        exit(1);
    }

    // State of the file
    fprintf(fPtr, "unlock | NOPASSWORD\n");

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
*/

void allfunctions(){
    if(!havewallet()) {
        gen_keys(pk, mk, seed);
        gen_address(pk);

        /*
         * PAS UTILE POUR LE MOMENT MAIS PEUT ETRE POUR LES TX
        PENSER A AJOUTER #include walletdatconfig.h OU walletdat_encrypt.h et walletdat_decrypt pour savoir si oui ou non le wallet est unlock
        #ifdef WALLETUNLOCK
            #undef WALLETLOCK
        */
        walletdat(pk, mk);
        encryptfile(false);
    }
    else{
        if(!cipherwallet){

            FILE *inputFile = fopen("wallet.dat", "rb");
            if (!inputFile) {
                errFile("Cannot open ", "wallet.dat");
            }

            char firstLine[300];
            fgets(firstLine, sizeof(firstLine), inputFile);

            if(strstr(firstLine, "NOPASSWORD")){
                encryptfile(false);
            }else{
                encryptfile(true);
            }

        }
        else{
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

                    sha256_fun((uint8_t *)userPassword, sha256_hash, 1, strlen(userPassword));  // Modification ici

                    char *hashpassword = showhex(sha256_hash, SHA256_DIGEST_LENGTH);
                    printf("sha256_hash ::: %s\n", hashpassword);

                    aes_file("enc_wallet.dat", hashpassword);
                    free(hashpassword);

                } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' ||
                           userResponse == 'NO') {
                    response=true;
                    printf("You have chosen not to decipher your enc_wallet.dat file.\n"
                           "If you change your mind, you can change it by typing command './gen_key_mode3'\n");
                } else {
                    printf("Invalid input. Please enter 'Y' or 'n'.\n");
                }
            }
        }

    }
}
int main(void) {


    allfunctions();


// Tester si le hash a bien fonctionne grace au powershell windows : Get-FileHash _PATH_/pk_key | Format-List . Spoiler, ca fonctionne

    return 0;
}

