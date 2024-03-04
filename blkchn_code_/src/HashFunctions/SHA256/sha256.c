#include "sha256.h"
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>

#include <openssl/sha.h>

int sha256_fun(uint8_t data[], unsigned char *hash, uint8_t rounds, size_t data_len) {

    for (int i = 0; i < rounds; ++i) {
        // Definition de la structure de donnees SHA256_CTX afin de stocker
        // des etats intermediaires internes pendant le processus de calcul du hachage.
        SHA256_CTX sha256_ctx;
        // Initialisation d'une valeur de hash H^(0) initiale
        SHA256_Init(&sha256_ctx);

        if(data==hash){
            // Calcul incrementiel du hash du message en fragments
            SHA256_Update(&sha256_ctx, data, SHA256_DIGEST_LENGTH);
            printf("pk==hash");
            // Calcul du hash final après que tous les fragments aient été hashés avec SHA256_Update
            SHA256_Final(hash, &sha256_ctx);

/*
            //S'ASSURER QUE LE HASH A BIEN FONCTIONNE :
            FILE *fPtr = fopen("./i_", "wb");
            fwrite(hash, sizeof(uint8_t), SHA256_DIGEST_LENGTH, fPtr);
            fclose(fPtr);

            //EXE LA COMMANDE :  Get-Content -Path ./i_ -Encoding Byte | ForEach-Object { '{0:X2}' -f $_ } | Out-File -FilePath ./i_hex
            //OUVRIR LE FICHIER ./i_hex et check la sortie 'SHA256(SHA256(pk))' avec le contenu du fichier
*/
        }else{
            // Calcul incrementiel du hash du message en fragments
            SHA256_Update(&sha256_ctx, data, data_len);
            // Calcul du hash final après que tous les fragments aient été hashés avec SHA256_Update
            SHA256_Final(hash, &sha256_ctx);
        }

        data = hash;
    }

    return 0;
}
