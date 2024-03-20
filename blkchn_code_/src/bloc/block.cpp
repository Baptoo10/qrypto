#include <ctime>
#include <string>

#include "block.hpp"

/*Block(int depth, std::string data, std::string previoushash) {
  this->depth = depth;
  this->date = std::time(NULL);
  this->data = data;
  this->previoushash = previoushash;
  
  FILE *f;
  string b="blabla.txt";
  f = fopen(b.c_str(), "wb");
  if (f == NULL)
    cout << "Impossible d'ouvrir le fichier en écriture !" << endl;
  else {

    fwrite(&depth, sizeof(int), 1, f);
    fwrite(&date, sizeof(string), 1, f);
    fwrite(&data, sizeof(string), 1, f);
    fwrite(&previoushash, sizeof(string), 1, f);
    fclose(f);
}
   
  Block::Block() {
this->depth = 0;
this->date = std::time(NULL);
this->data = "Genesis Block";
  FILE *f;
  f = fopen("toto.txt", "wb");
  if (f == NULL)
    cout << "Impossible d'ouvrir le fichier en écriture !" << endl;
  else {

    fwrite(&depth, sizeof(int), 1, f);
    fwrite(&date, sizeof(string), 1, f);
    fwrite(&data, sizeof(string), 1, f);
    fwrite(&previoushash, sizeof(string), 1, f);
    fclose(f);
}
*/
// Block generatenextblock(std::string data) {}

// void Block::validation() {}
