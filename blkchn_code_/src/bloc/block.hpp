#include <cstdio>
#include <iostream>
#include <string>
#include <ctime>
#include <fstream>


using namespace std;

class Block {

public:
  int depth;
  int date;
  char* data;
  char* hash;
  char* previoushash;

Block(int depth, char* data, char* previoushash){
  this->depth = depth;
  this->date = std::time(NULL);
  this->data = data;
  this->previoushash = previoushash;
  string a="block_"+to_string(depth)+".txt";
  const char* b=a.c_str();
  
  FILE *f = fopen(b, "wb");
  
    
  //  f = fopen(b.c_str(), "wb");
    if (f == NULL)
      cout << "Impossible d'ouvrir le fichier en écriture !" << endl;
    else {
      cout << "AAImpossible d'ouvrir le fichier en écriture !" << depth << endl;
    fprintf(f, "%d \n", depth);
    fprintf(f, "%d \n", date);
    fprintf(f, "%s\n", data);
    fprintf(f, "%s\n", previoushash);
    fclose(f);
  }

  FILE *g;
  b="lastblock.txt";
  g = fopen(b, "wb");
  if (g == NULL)
    cout << "Impossible d'ouvrir le fichier en écriture !";
  else {
    fprintf(g, "%d \n", depth);
    fprintf(g, "%d \n", date);
    fprintf(g, "%s\n", data);
    fprintf(g, "%s\n", previoushash);
    fclose(g);
  }
  
}

 Block(){
this->depth = 0;
this->date = std::time(NULL);
this->data = "Genesis Block";
   FILE *f;
   string b="block_0.txt";
   f = fopen(b.c_str(), "wb");
   if (f == NULL)
     cout << "Impossible d'ouvrir le fichier en écriture !";
   else {
     cout << "Voici data:" << data << endl;
    fprintf(f, "%d \n", depth);
    fprintf(f, "%d \n", date);
    fprintf(f, "%s\n", data);
    fclose(f);
   }
  FILE *g;
  b="lastblock.txt";
  
  g = fopen(b.c_str(), "w");
  if (g == NULL)
    cout << "Impossible d'ouvrir le fichier en écriture !";
  else {
    
    fprintf(g, "%d \n", depth);
    fprintf(g, "%d \n", date);
    fprintf(g, "%s\n", data);
    fclose(g);
  }
  }
};
/*Block generateNextBlock(string data){
  Pour pouvoir récupérer le dernier bloc pour avoir sa depth et son hash, faire une liste? Ou alors lors du genesisblock, créer un bloc "factice" lastblock qui contiendra toujours la meme chose que le dernier bloc créé et qui sera actualisé à chaque nouvelle instanciation
}*/
 // void validation()verifier depth, hash et previoushash;
