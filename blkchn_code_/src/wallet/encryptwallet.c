#include "config.h"

#include "encryptwallet.h"
#include "walletdat_aes.h"
#include "leveldb/c.h"

#include "../HashFunctions/SHA256/sha256.h"
#include "../print_type/printtype.h"

#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

char *showhex(const uint8_t a[], int size);
bool isPswdGood(const char *password);
void encryptfile(bool HasAlreadyBeenCipher);


void encryptfile(bool HasAlreadyBeenCipher){

    char userResponse;
    bool response = false;

    while (!response) {

        if(!HasAlreadyBeenCipher) {
            printf("Do you want to encrypt your wallet file with AES (recommended) ? [Y/n] ");
            scanf(" %s", &userResponse);

            if (userResponse == 'Y' || userResponse == 'y' || userResponse == 'Yes' || userResponse == 'yes' ||
                userResponse == 'YES') {
                response = true;
                printf("You have chosen to encrypt the wallet.dat file.\n");

                char userPassword[100];

                do {
                    printf("Choose a password (100 characters max) : ");
                    scanf(" %s", &userPassword);

                } while (!isPswdGood(userPassword));

                sha256_fun((uint8_t *) userPassword, sha256_hash, 1, strlen(userPassword));  // Modification ici

                char *hashpassword = showhex(sha256_hash, SHA256_DIGEST_LENGTH);

                printf("sha256_hash ::: %s\n", hashpassword);

                aes_file("wallet.dat", hashpassword);
                free(hashpassword);

            } else if (userResponse == 'N' || userResponse == 'n' || userResponse == 'No' || userResponse == 'no' ||
                       userResponse == 'NO') {
                response = true;
                printf("You have chosen not to encrypt the wallet.dat file.\n"
                       "If you change your mind, you can change it by typing command './gen_key_mode3'\n");

                makeFileReadOnly("wallet.dat");
            }
            else {
                printf("Invalid input. Please enter 'Y' or 'n'.\n");
            }
        }
        else{
            char userPassword[100];

            printf("If you want to make your wallet encrypted, please, enter your password (max 100 charac) : ");
            scanf(" %s", &userPassword);
            sha256_fun((uint8_t *) userPassword, sha256_hash, 1, strlen(userPassword));  // Modification ici

            char *hashpassword = showhex(sha256_hash, SHA256_DIGEST_LENGTH);

            printf("sha256_hash ::: %s\n", hashpassword);

            aes_file("wallet.dat", hashpassword);
            free(hashpassword);

            exit(0);
        }

    }

}

bool isPswdGood(const char *password) {

    bool hasGoodLength = false;
    bool hasUpperCase = false;
    bool hasLowerCase = false;
    bool hasDigit = false;
    bool hasSpecialChar = false;

    if (strlen(password) >= 12) {
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
