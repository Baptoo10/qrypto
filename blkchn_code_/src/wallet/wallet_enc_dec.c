#include "wallet_enc_dec.h"
#include "config.h"

#include "../sqlite_amalgamation_3450200/sqlite3.h"

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "../print_type/printtype.h"

#include "../avx2_dilithium3-AES-R/sign.h"


/*
/********************************************************
 *                                                      *
 *                     SQLCIPHER                        *
 *                                                      *
/********************************************************
*/

/*
 * Create the wallet database
 */
void sql_walletdat(uint8_t pk[], uint8_t sk[], char *userpswd, bool mustencrypt, char *finale_address) {

    sqlite3 *dec_db;
    int rc;

    // Open the non cipher database
    rc = sqlite3_open("dec_qptwallet.dat", &dec_db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Creation of the table qptwallet
    char *sql = "CREATE TABLE IF NOT EXISTS qptwallet (idwallet INTEGER PRIMARY KEY AUTOINCREMENT, raw_public_key BLOB, raw_secret_key BLOB,"
                " hex_public_key TEXT, hex_secret_key TEXT, address TEXT);";
    rc = sqlite3_exec(dec_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Insert data into qptwallet table
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
    rc = sqlite3_bind_text(stmt, 5, finale_address, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Can't execute statement: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(dec_db);

    // if user have chosen to encrypt his wallet
    if(mustencrypt){
        enc_walletdat(userpswd);
    }
}

/*
 * Encrypt a wallet database
 */
void enc_walletdat(char *userpswd) {

    sqlite3 *dec_db;
    int rc;
    char attach_db[200];

    // Open the non cipher database
    rc = sqlite3_open("dec_qptwallet.dat", &dec_db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Attach the cipher bdd
    snprintf(attach_db, sizeof(attach_db), "ATTACH DATABASE 'enc_qptwallet.dat' AS encrypted KEY '%s';", userpswd);
    rc = sqlite3_exec(dec_db, attach_db, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't attach database because your password is probably wrong (or %s)\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Creation of the table qptwallet
    char *sql = "CREATE TABLE IF NOT EXISTS encrypted.qptwallet (idwallet INTEGER PRIMARY KEY AUTOINCREMENT, raw_public_key BLOB, raw_secret_key BLOB,"
                " hex_public_key TEXT, hex_secret_key TEXT, address TEXT);";
    rc = sqlite3_exec(dec_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Insert data from non cipher db into cipher one (from qptwallet table)
    sql = "INSERT INTO encrypted.qptwallet SELECT * FROM qptwallet;";
    rc = sqlite3_exec(dec_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't insert data: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    // Detach the cipher db
    rc = sqlite3_exec(dec_db, "DETACH DATABASE encrypted;", NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't detach database: %s\n", sqlite3_errmsg(dec_db));
        sqlite3_close(dec_db);
        exit(1);
    }

    sqlite3_close(dec_db);

    // remove dec_qptwallet.dat file
    shell_command("rm -f dec_qptwallet.dat");
}

/*
 * Decrypt a wallet database
 */
void dec_walletdat(char *userpswd) {

    sqlite3 *enc_db;
    char *err_msg = 0;
    int rc;
    char attach_db[200];
    char key[100];

    // Open the cipher database
    rc = sqlite3_open("enc_qptwallet.dat", &enc_db);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Define the cipher key
    snprintf(key, sizeof(key), "PRAGMA key = '%s';", userpswd);
    rc = sqlite3_exec(enc_db, key, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't set PRAGMA key: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Attach the non cipher bdd
    snprintf(attach_db, sizeof(attach_db), "ATTACH DATABASE 'dec_qptwallet.dat' AS decrypted KEY '';");
    rc = sqlite3_exec(enc_db, attach_db, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't attach database because your password is probably wrong (or %s)\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Creation of the table qptwallet
    char *sql = "CREATE TABLE IF NOT EXISTS decrypted.qptwallet (idwallet INTEGER PRIMARY KEY AUTOINCREMENT, raw_public_key BLOB, raw_secret_key BLOB,"
                " hex_public_key TEXT, hex_secret_key TEXT, address TEXT);";
    rc = sqlite3_exec(enc_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't create table: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Insert data from non cipher db into cipher one (from qptwallet table)
    sql = "INSERT INTO decrypted.qptwallet SELECT * FROM qptwallet;";
    rc = sqlite3_exec(enc_db, sql, NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't insert data: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    // Detach the cipher db
    rc = sqlite3_exec(enc_db, "DETACH DATABASE decrypted;", NULL, 0, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Can't detach database: %s\n", sqlite3_errmsg(enc_db));
        sqlite3_close(enc_db);
        exit(1);
    }

    sqlite3_close(enc_db);

    // remove enc_qptwallet.dat file
    shell_command("rm -f enc_qptwallet.dat");
}