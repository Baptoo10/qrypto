#include "ripemd160.h"

#include <stdint.h>

#include <openssl/ripemd.h>

int ripemd160_fun(uint8_t data[], unsigned char *hash, uint8_t rounds) {

    for (int i = 0; i < rounds; ++i) {

        RIPEMD160_CTX ripemd160_ctx;
        // Initialisation d'une valeur de hash
        RIPEMD160_Init(&ripemd160_ctx);
        // Calcul incrementiel du hash du message en fragments
        RIPEMD160_Update(&ripemd160_ctx, data, RIPEMD160_DIGEST_LENGTH);
        // Calcul du hash final après que tous les fragments aient été hashés avec RIPEMD160_Update
        RIPEMD160_Final(hash, &ripemd160_ctx);

        data = hash;
    }
    return 0;
}