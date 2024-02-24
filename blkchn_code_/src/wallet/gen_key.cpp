#include <iostream>
#include <dlfcn.h>
#include <cstdint>

extern "C" {
#include "../avx2_dilithium3-AES-R/api.h"
}


extern "C" int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int gen_keys();

int main() {
    // Loading library libpqcrystals_aes256ctr_avx2.so
    void* libHandle = dlopen("../avx2_dilithium3-AES-R/libpqcrystals_aes256ctr_avx2.so", RTLD_NOW);
    if (!libHandle) {
        std::cerr << "Impossible de charger la bibliothèque : " << dlerror() << std::endl;
        return 1;
    }

    int result = gen_keys();

    // close the library
    dlclose(libHandle);

    return result;
}

int gen_keys() {

    // Buffers declaration for keys
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[CRYPTO_SECRETKEYBYTES];

    // Generation of the keys
    if (crypto_sign_keypair(public_key, secret_key) != 0) {
        std::cerr << "Erreur lors de la génération de la paire de clés." << std::endl;
        return 1;
    }

    // Display the keys
    std::cout << "Clé publique : ";
    for (std::size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i)
        std::cout << std::hex << static_cast<int>(public_key[i]);
    std::cout << std::endl;

    std::cout << "Clé privée : ";
    for (std::size_t i = 0; i < CRYPTO_SECRETKEYBYTES; ++i)
        std::cout << std::hex << static_cast<int>(secret_key[i]);
    std::cout << std::endl;

    return 0;
}
