#include "wal.h"

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdbool.h>

void errFile(const char *errmessage, const char *filename) {
    fprintf(stderr, "Error : %s %s\n", errmessage, filename);
    exit(1);
}

void err(void) {
    exit(1);
}


void deriveKeyFromPassword(const char *password, unsigned char *key, unsigned char *iv) {
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                       (const unsigned char *)password, strlen(password), 1, key, iv) != KEY_SIZE) {
        err();
    }
}


void aes_file(const char *inputFilename, const char *password) {

    FILE *inputFile = fopen(inputFilename, "rb");
    if (!inputFile) {
        errFile("Cannot open ", inputFilename);
    }

    char outputFilename[300];
    char enc[] = "enc_";

    char firstLine[300];
    fgets(firstLine, sizeof(firstLine), inputFile);

    if(!strstr(firstLine, "NOPASSWORD")){
        if(!strstr(firstLine, password)){
            printf("Wrong password\n");
            exit(1);
        }
    }

    bool crypttype;

    if (strstr(firstLine, "unlock") != NULL){
        crypttype = true;  // Must encrypt the file
        sprintf(outputFilename, "%s%s", enc, inputFilename);
        printf("Encryption in progress.\n");
    }
    else if (strstr(firstLine, "lock") != NULL){
        crypttype = false;  // Must decrypt the file

        size_t pos = strstr(inputFilename, enc) - inputFilename;
        strcpy(outputFilename, inputFilename);

        if (pos != -1){
            memmove(outputFilename+pos, outputFilename + pos + strlen(enc), strlen(outputFilename+pos+strlen(enc)) + 1);
            printf("inputFilename : %s | outputFilename : %s\n", inputFilename, outputFilename);
        }

        printf("Decryption in progress.\n");
    }
    else{
        fprintf(stderr, "Invalid mode found in the file.\n");
        exit(1);
    }

    FILE *outputFile = fopen(outputFilename, "wb");
    if (!outputFile){
        errFile("Cannot open ", outputFilename);
    }

    // Generate key and iv from password
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    deriveKeyFromPassword(password, key, iv);

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (crypttype) {
        // Initialization of the cipher context
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            err();
        }
    }
    else if (!crypttype) {
        // Initialization of the decipher context
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
            err();
        }
    }

    unsigned char buffer[1024];
    int bytesRead, cipherTextLength, clearTextLength;
    unsigned char cipherText[1024 + EVP_MAX_BLOCK_LENGTH], clearText[1024 + EVP_MAX_BLOCK_LENGTH];

    if (crypttype) { // If the file is encrypted, must decrypt it and write "unlock" on the first line
        // Write "lock" as the first line
        fprintf(outputFile, "lock | %s\n", password);
    }
    else if (!crypttype) { // If the file is decrypted, must encrypt it and write "lock" on the first line
        // Write "unlock" as the first line
        fprintf(outputFile, "unlock | %s\n", password);
    }

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), inputFile)) > 0) {
        if (crypttype) {
            if (EVP_EncryptUpdate(ctx, cipherText, &cipherTextLength, buffer, bytesRead) != 1) {
                err();
            }
            // Writing the ciphertext in the outputFile
            fwrite(cipherText, 1, cipherTextLength, outputFile);
        }
        else if (!crypttype) {
            if (EVP_DecryptUpdate(ctx, clearText, &clearTextLength, buffer, bytesRead) != 1) {
                err();
            }
            // Writing the cleartext in the outputFile
            fwrite(clearText, 1, clearTextLength, outputFile);
        }
    }

    if (crypttype) {
        // Ending the encryption
        if (EVP_EncryptFinal_ex(ctx, cipherText, &cipherTextLength) != 1) {
            err();
        }

        // Writing the last part of the ciphertext in the outputFile
        fwrite(cipherText, 1, cipherTextLength, outputFile);

        remove(inputFilename);
    }
    else if (!crypttype) {
        // Ending the decryption
        if (EVP_DecryptFinal_ex(ctx, clearText, &clearTextLength) != 1) {
            err();
        }

        // Writing the last part of the decrypted text in the outputFile
        fwrite(clearText, 1, clearTextLength, outputFile);

        remove(inputFilename);
    }

    printf("outputFilename : %s\n", outputFilename);
    makeFileReadOnly(outputFilename);

    EVP_CIPHER_CTX_free(ctx);
    fclose(inputFile);
    fclose(outputFile);
}
/*
int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf(stderr, "utilisation : %s <filename> <password>\n", argv[0]);
        return 1;
    }

    char *inputFilename = argv[1];
    char *password = argv[2];

    aes_file(inputFilename, password);

    return 0;

}
*/