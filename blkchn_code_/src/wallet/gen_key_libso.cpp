#include <iostream>
#include <dlfcn.h>
#include <cstdint>

// Include the Dilithium API header
#ifdef __cplusplus
extern "C" {
#endif

#include "../avx2_dilithium3-AES-R/api.h"
#include "../avx2_dilithium3-AES-R/fips202x4.h"

#ifdef __cplusplus
}
#endif
// Function to generate keys
int gen_keys();

int main() {
    // Loading the Dilithium library
    /* void* libHandle = dlopen("../lib/libpqcrystals_dilithium3aes_avx2.so", RTLD_NOW);
     if (!libHandle) {
         std::cerr << "Failed to load Dilithium library: " << dlerror() << std::endl;
         return 1;
     }
 */
    int result = gen_keys();

    // Close the library
    //   dlclose(libHandle);

    return result;
}

int gen_keys() {
    // Buffers declaration for keys
    unsigned char public_key[CRYPTO_PUBLICKEYBYTES];
    unsigned char secret_key[CRYPTO_SECRETKEYBYTES];

    // Load the key generation function from the library
    auto keypair_function = reinterpret_cast<decltype(&crypto_sign_keypair)>(
            dlsym(RTLD_DEFAULT, "pqcrystals_dilithium3aes_r_avx2_keypair")
    );

    if (!keypair_function) {
        std::cerr << "Failed to load keypair function: " << dlerror() << std::endl;
        return 1;
    }

    // Generation of the keys using the loaded function
    if (keypair_function(public_key, secret_key) != 0) {
        std::cerr << "Error during key generation." << std::endl;
        return 1;
    }

    // Display the keys
    std::cout << "Public key: ";
    for (std::size_t i = 0; i < CRYPTO_PUBLICKEYBYTES; ++i)
        std::cout << std::hex << static_cast<int>(public_key[i]);
    std::cout << std::endl;

    std::cout << "Secret key: ";
    for (std::size_t i = 0; i < CRYPTO_SECRETKEYBYTES; ++i)
        std::cout << std::hex << static_cast<int>(secret_key[i]);
    std::cout << std::endl;

    return 0;
}
