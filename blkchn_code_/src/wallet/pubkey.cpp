
#include "pubkey.h"

#include <iostream>
#include <cstdio>
#include <cstring>
extern "C"{
    #include "gen_key.h"
}

int main(){
    gen_keys();
}

/*
int main() {

    FILE *pipe = popen("./gen_key_mode3", "r");

    if (!pipe) {
        std::cerr << "Erreur lors de l'exécution de gen_key_mode3." << std::endl;
        return 1;
    }

    // Lecture de la sortie de gen_key_mode3
    char buffer[128];
    std::string result = "";

    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }

    // Fermeture du flux
    pclose(pipe);

    // Affichage de la sortie
    std::cout << "Sortie de gen_key_mode3 : \n" << result << std::endl;

    return 0;
}
*/