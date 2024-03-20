#include "block.hpp"
#include <cstdio>
#include <iostream>
#include <cstdio>
using namespace std;

int main() {
  
    FILE* fichierbis = fopen("test.txt", "w");
    int a=3;
    char* b="abcde fgh";
    if (fichierbis != nullptr) {
        // Écrire des données dans le fichier
        fprintf(fichierbis, "Exemple de donnees e sauvegarder %d\n", a);
        
        fprintf(fichierbis, "Exemple de donnees a sauvegarder %s\n", b);
    }
fclose(fichierbis); 
  cout << "Hello World!\n";

  Block genesisblock;
  Block block1(1, "blabla", "heho");
  Block block2(2, "blabla", "bloup");

  char *nomDuFichier = "block_2.txt";

  // Variables pour stocker les données lues
  int depth;
  char* date;
  char* data;
  char* previoushash;

  FILE *fichier = fopen(nomDuFichier, "rb");

  if (fichier != nullptr) {
    char buffer[1024];
    std::size_t bytesRead;
    while ((bytesRead = std::fread(buffer, 1, sizeof(buffer), fichier)) > 0) {
      std::fwrite(buffer, 1, bytesRead, stdout);
    }
    std::fclose(fichier);

  } else {
    std::cerr << "Erreur lors de l'ouverture du fichier." << endl;
  }

  return 0;
}
