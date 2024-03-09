#include "config.h"

#include "encryptwallet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

bool isPswdGood(const char *password);
void encryptfile();


void makeFileReadOnly(const char *filename) {
    #ifdef _WIN32
        SetFileAttributes(filename.c_str(), FILE_ATTRIBUTE_READONLY);
    #elif defined(__linux__) || defined(__linux)
        chmod(filename, S_IRUSR | S_IRGRP | S_IROTH);
    #endif
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

            const char userPassword[100];

            do {
                printf("Choose a password (100 characters max) : ");
                scanf(" %s", &userPassword);

            } while (!isPswdGood(userPassword));

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

            makeFileReadOnly("wallet.dat");
        }
        else {
            printf("Invalid input. Please enter 'Y' or 'n'.\n");
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
