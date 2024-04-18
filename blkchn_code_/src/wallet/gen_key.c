/*
 * Actual pb :
 * encrypt a file already made (<=> encrypt a plain database)
 * decrypt a database (maybe it's working but not sure)
 *
 */


#include "config.h"
//#include "leveldb/c.h"
#include <assert.h>

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

#include "../HashFunctions/SHA256/sha256.h"
#include "../HashFunctions/RIPEMD160/ripemd160.h"

#include "../avx2_dilithium3-AES-R/sign.h"

#include "../base58/base58.h"

#include "../print_type/printtype.h"

//#include "encryptwallet.h"
//#include "walletdat_aes.h"

uint8_t mk[CRYPTO_MASTERSECRETKEYBYTES];
uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t seed[3 * SEEDBYTES];

unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];


char *addr_cat_crf = NULL;
bool cipherwallet;

int gen_keys(uint8_t pk[], uint8_t sk[], uint8_t seed[]);
void encodageb58(unsigned char *chainid_ripemd160_fb, size_t chainid_ripemd160_fb_len, const uint16_t addr_type);
bool isPswdGood(const char *password);
char* ChooseToEncryptFile(bool HasAlreadyBeenCipher);
void allfunctions();

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



/*
/********************************************************
 *                                                      *
 *                  SQLITE SEE                          *
 *                                                      *
/********************************************************
*/

/*
 * Encrypt an existing wallet database
 */
int encryptDatabase(const char *dbPath, const void *password, int nKey) {
    sqlite3 *db;
    int rc;

    // Ouvre la base de données SQLite
    rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    // Définit la clé de chiffrement pour la base de données
    rc = sqlite3_key(db, password, nKey);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to set encryption key: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    // Rechiffre la base de données avec la nouvelle clé (la même dans ce cas)
    rc = sqlite3_rekey(db, password, nKey);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to encrypt database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    // Ferme la connexion à la base de données
    sqlite3_close(db);
    return SQLITE_OK; // Opération réussie
}
/*
int encryptDatabase(char *existingWallet, char *userpswd) {
    sqlite3 *db;
    char *errMsg = 0;

    int rc = sqlite3_open(existingWallet, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    rc = sqlite3_key(db, userpswd, strlen(userpswd));
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Error setting key: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return rc;
    }

    sqlite3_close(db);

    return SQLITE_OK;
}
*/

// Must create a new table for tx, later (with data like 'inputtx BLOB' and 'outputtx BLOB')
/*
 * Encrypt a new wallet database
 */
void enc_walletdat(uint8_t pk[], uint8_t sk[], char *userpswd) {

    printf("us pwd : %s", userpswd);

    sqlite3 *enc_db;
    char *err_msg = 0;
    int rc;

    rc = sqlite3_open("enc_qptwallet.dat", &enc_db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Define the cipher key
    rc = sqlite3_key(enc_db, userpswd, strlen(userpswd));
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot set database key: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    char *sql = "CREATE TABLE IF NOT EXISTS qptwallet (idwallet INTEGER PRIMARY KEY AUTOINCREMENT, raw_public_key BLOB, raw_secret_key BLOB,"
                " hex_public_key TEXT, hex_secret_key TEXT, address TEXT);";
    rc = sqlite3_exec(enc_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    sql = "INSERT INTO qptwallet (raw_public_key, raw_secret_key, hex_public_key, hex_secret_key, address) VALUES (?,?,?,?,?);";
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(enc_db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't prepare statement: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    rc = sqlite3_bind_blob(stmt, 1, pk, CRYPTO_PUBLICKEYBYTES, -1);
    rc = sqlite3_bind_blob(stmt, 2, sk, CRYPTO_SECRETKEYBYTES, -1);
    rc = sqlite3_bind_text(stmt, 3, showhex(pk, CRYPTO_PUBLICKEYBYTES), -1, SQLITE_STATIC);
    rc = sqlite3_bind_text(stmt, 4, showhex(sk, CRYPTO_SECRETKEYBYTES), -1, SQLITE_STATIC);
    rc = sqlite3_bind_text(stmt, 5, addr_cat_crf, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Can't execute statement: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(enc_db);

}

/*
 * Decrypt a wallet database
 */
void dec_walletdat(uint8_t pk[], uint8_t sk[], bool HasAlreadyBeenEncrypted, char *userpswd) {

    sqlite3 *dec_db;
    char *err_msg = 0;
    int rc;

    // If the user doesn't want to encrypt his database
    if(!HasAlreadyBeenEncrypted) {
        //create a plaintext qptwallet
        rc = sqlite3_open("dec_qptwallet.dat", &dec_db);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        char *sql = "CREATE TABLE IF NOT EXISTS qptwallet (idwallet INTEGER PRIMARY KEY AUTOINCREMENT, raw_public_key BLOB, raw_secret_key BLOB,"
                    " hex_public_key TEXT, hex_secret_key TEXT, address TEXT);";
        rc = sqlite3_exec(dec_db, sql, NULL, 0, NULL);

        if (rc != SQLITE_OK) {
            fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        sql = "INSERT INTO qptwallet (raw_public_key, raw_secret_key, hex_public_key, hex_secret_key, address) VALUES (?,?,?,?,?);";
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(dec_db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Can't prepare statement: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        rc = sqlite3_bind_blob(stmt, 1, pk, CRYPTO_PUBLICKEYBYTES, -1);
        rc = sqlite3_bind_blob(stmt, 2, sk, CRYPTO_SECRETKEYBYTES, -1);
        rc = sqlite3_bind_text(stmt, 3, showhex(pk, CRYPTO_PUBLICKEYBYTES), -1, SQLITE_STATIC);
        rc = sqlite3_bind_text(stmt, 4, showhex(sk, CRYPTO_SECRETKEYBYTES), -1, SQLITE_STATIC);
        rc = sqlite3_bind_text(stmt, 5, addr_cat_crf, -1, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "Can't execute statement: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        sqlite3_finalize(stmt);
        sqlite3_close(dec_db);

    }
    // If the user wants to decrypt his database
    else{
        // Ouvrez la base de données chiffrée
        rc = sqlite3_open("enc_qptwallet.dat", &dec_db);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot open encrypted database: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        // Définir la clé de déchiffrement
        rc = sqlite3_key(dec_db, userpswd, strlen(userpswd));
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot set database key for decryption: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        // Ouvrez la nouvelle base de données non chiffrée
        rc = sqlite3_open("dec_qptwallet.dat", &dec_db);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Cannot open decrypted database: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            exit(1);
        }

        // Copiez le contenu déchiffré de la base de données chiffrée vers la base de données non chiffrée
        const char *sql = "ATTACH DATABASE 'dec_qptwallet.dat' AS dec_db;"
                          "CREATE TABLE dec_db.qptwallet AS SELECT * FROM main.qptwallet;";
        rc = sqlite3_exec(dec_db, sql, NULL, 0, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "Error copying decrypted data: %s\n", sqlite3_errmsg(dec_db));
            sqlite3_close(dec_db);
            sqlite3_close(dec_db);
            exit(1);
        }

        printf("Decryption successful. Encrypted table copied to unencrypted database.\n");

        // Fermez la connexion à la base de données chiffrée
        sqlite3_close(dec_db);
        // Fermez la connexion à la base de données non chiffrée
        sqlite3_close(dec_db);
    }
}

/*
 * Decrypt qptwallet.dat
 */
void DecryptDatabase(const char* dbName, const char* key) {
    sqlite3* db;
    int rc = sqlite3_open(dbName, &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Erreur lors de l'ouverture de la base de données: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Définit la clé de chiffrement avec le mot de passe fourni
    rc = sqlite3_key(db, key, strlen(key));
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Erreur lors de la définition de la clé de chiffrement: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Récupère le contenu de la base de données
    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, "SELECT * FROM qptwallet", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Erreur lors de la préparation de la requête: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Crée un fichier pour le contenu déchiffré
    FILE* decFile = fopen("dec_qptwallet.dat", "wb");
    if (decFile == NULL) {
        fprintf(stderr, "Erreur lors de la création du fichier de déchiffrement.\n");
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }

    // Écrit le contenu déchiffré dans le fichier
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char* data = sqlite3_column_blob(stmt, 0);
        int dataSize = sqlite3_column_bytes(stmt, 0);
        fwrite(data, sizeof(unsigned char), dataSize, decFile);
    }

    // Finalise la requête
    sqlite3_finalize(stmt);

    // Ferme le fichier et la base de données
    fclose(decFile);
    sqlite3_close(db);
}



/*
 * Check if the wallet is encrypted
 */
bool IsWalletEncrypted(bool enc){
    sqlite3 *db;
    char *errMsg = 0;
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
    const char *query = "SELECT * FROM qptwallet;";

    rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare query: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }

    rc = sqlite3_step(stmt);
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
        gen_keys(pk, mk, seed);
        gen_address(pk);

        char* userPassword=ChooseToEncryptFile(false);

        if(userPassword!=NULL){
            printf("Password: %s\n", userPassword);
            enc_walletdat(pk, mk, userPassword);
        }
        else{
            dec_walletdat(pk, mk, false, NULL);
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

                    char* userPassword_[100];

                    printf("\nPlease, enter your password (max 100 charac) : ");
                    scanf("%s", userPassword_);
                    printf("user password : %s\n", userPassword_);

                    encryptDatabase("dec_qptwallet.dat", userPassword_);

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
                    DecryptDatabase("enc_qptwallet.dat", userPassword);

                    //dec_walletdat(pk, mk, true, userPassword_);

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

