#include "walletdat_encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <openssl/evp.h>

#define KEY_SIZE 32 //key size = 256 bits
#define IV_SIZE 16 //initialized vector size = 128 bits

void handleErrors(void)
{
    perror("Error");
    exit(1);
}

void generateRandomBytes(unsigned char *buffer, size_t size)
{
    if (RAND_bytes(buffer, size) != 1)
    {
        handleErrors();
    }
}


void deriveKeyFromPassword(const char *password, unsigned char *key, unsigned char *iv)
{
    // Générer la clé et le vecteur d'initialisation (IV) à partir du mot de passe
    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                       (unsigned char *)password, strlen(password), 1, key, iv) != KEY_SIZE)
    {
        handleErrors();
    }
}


void encrypt(const char *filename, const char *password){

    FILE *wallet_file = fopen(filename, "rb+"); // Ouvre le fichier en mode lecture/écriture binaire

    if (!wallet_file) {
        perror("Error opening file");
        exit(1);
    }

    if (ferror(wallet_file)) {
        perror("Error reading file");
        fclose(wallet_file);
        exit(1);
    }


    // Générer la clé et le vecteur d'initialisation (IV) de manière aléatoire
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    generateRandomBytes(key, KEY_SIZE);
    generateRandomBytes(iv, IV_SIZE);

    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                       (unsigned char *)password, strlen(password), 1, key, iv) != KEY_SIZE) {
        handleErrors();
    }

    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, KEY_SIZE * 8, &aesKey) != 0)
    {
        handleErrors();
    }

    // Tampon pour stocker les données lues à partir du fichier
    unsigned char buffer[1024];
    int bytesRead;
    unsigned char cipherText[1024];

    // Lire le fichier par blocs et chiffrer chaque bloc
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), wallet_file)) > 0)
    {
        AES_cbc_encrypt(buffer, cipherText, bytesRead, &aesKey, iv, AES_ENCRYPT);

        // Déplacer le curseur de fichier à la position actuelle pour écrire les données chiffrées
        fseek(wallet_file, -bytesRead, SEEK_CUR);

        // Écrire les données chiffrées dans le fichier
        fwrite(cipherText, 1, bytesRead, wallet_file);
    }

    fclose(wallet_file);
}

void decrypt(const char *filename, const char *password)
{
    FILE *wallet_file = fopen(filename, "rb+"); // Ouvre le fichier en mode lecture/écriture binaire

    if (!wallet_file)
    {
        perror("Error opening file");
        exit(1);
    }

    if (ferror(wallet_file))
    {
        perror("Error reading file");
        fclose(wallet_file);
        exit(1);
    }

    // Générer la clé et le vecteur d'initialisation (IV) à partir du mot de passe
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    deriveKeyFromPassword(password, key, iv);

    AES_KEY dec_aesKey;
   /* if (AES_set_decrypt_key(key, KEY_SIZE * 8, &dec_aesKey) != 0) {
        handleErrors();
    }

   */

    AES_set_decrypt_key(key, KEY_SIZE * 8, &dec_aesKey);

    // Tampon pour stocker les données lues à partir du fichier
    unsigned char buffer[64];
    int bytesRead;
    unsigned char decryptedText[64];

    // Lire le fichier par blocs et déchiffrer chaque bloc
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), wallet_file)) > 0) {
        // Déchiffrer le bloc
        AES_cbc_encrypt(buffer, decryptedText, bytesRead, &dec_aesKey, iv, AES_DECRYPT);

        // Réinitialiser la position du curseur au début du bloc actuel
        fseek(wallet_file, -bytesRead, SEEK_CUR);

        // Écrire les données déchiffrées dans le fichier
        fwrite(decryptedText, 1, bytesRead, wallet_file);

        // Déplacer le curseur de fichier à la position suivante pour la lecture suivante
        fseek(wallet_file, bytesRead, SEEK_CUR);
    }

    fclose(wallet_file);
}


int main(){

    const char *filename = "test.txt";
    const char *password = "oui";

    // Chiffrer le fichier
    encrypt(filename, password);

    printf("Encryption successful.\n");

    // Déchiffrer le fichier
    decrypt(filename, password);

    printf("Decryption successful.\n");

    return 0;
}
