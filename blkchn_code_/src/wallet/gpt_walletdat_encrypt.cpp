#include "gpt_walletdat_encrypt.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <openssl/evp.h>

#define KEY_SIZE 32
#define IV_SIZE 16

void handleErrors()
{
    std::cerr << (stderr);
    exit(1);
}

void encryptFile(const std::string &inputFilename, const std::string &outputFilename, const std::string &password)
{
    std::ifstream inputFile(inputFilename, std::ios::binary);
    std::ofstream outputFile(outputFilename, std::ios::binary);

    if (!inputFile || !outputFile)
    {
        std::cerr << "Error opening file" << std::endl;
        exit(1);
    }

    // Générer la clé et le vecteur d'initialisation (IV) à partir du mot de passe
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    if (EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                       reinterpret_cast<const unsigned char *>(password.c_str()), password.length(), 1, key, iv) != KEY_SIZE)
    {
        handleErrors();
    }

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    // Initialiser le contexte de chiffrement
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1)
    {
        handleErrors();
    }

    // Tampon pour stocker les données lues à partir du fichier
    unsigned char buffer[1024];
    int bytesRead, cipherTextLength;
    unsigned char cipherText[1024 + EVP_MAX_BLOCK_LENGTH];

    // Lire le fichier par blocs et chiffrer chaque bloc
    while ((bytesRead = inputFile.readsome(reinterpret_cast<char *>(buffer), sizeof(buffer))) > 0)
    {
        if (EVP_EncryptUpdate(ctx, cipherText, &cipherTextLength, buffer, bytesRead) != 1)
        {
            handleErrors();
        }

        // Écrire le texte chiffré dans le fichier de sortie
        outputFile.write(reinterpret_cast<const char *>(cipherText), cipherTextLength);
    }

    // Finaliser le chiffrement
    if (EVP_EncryptFinal_ex(ctx, cipherText, &cipherTextLength) != 1)
    {
        handleErrors();
    }

    // Écrire la dernière partie du texte chiffré dans le fichier de sortie
    outputFile.write(reinterpret_cast<const char *>(cipherText), cipherTextLength);

    // Libérer les ressources
    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <input_filename> <output_filename> <password>" << std::endl;
        return 1;
    }

    const std::string inputFilename = argv[1];
    const std::string outputFilename = argv[2];
    const std::string password = argv[3];

    encryptFile(inputFilename, outputFilename, password);

    std::cout << "Encryption successful." << std::endl;

    return 0;
}

