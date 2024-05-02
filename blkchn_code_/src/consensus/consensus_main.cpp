#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <stdbool.h>
#include <iomanip>
#include <map>
#include <cstdio>
#include <fstream>

#include <openssl/sha.h>

#include "../HashFunctions/SHA256/sha256_file.h"
#include "../print_type/printtype.h"

// Utilisation de leveldb pour stocker le dictionnaire (push_back tous les hash dans ce cas ? => check de
// l'espace que ca prend mais pas obligatoire sinon, chaque thread realisera 128 verifications et donc on pourra alors renommer
// la variable nb_blocks en nb_threads)

using namespace std;

// a block is 128 threads. Then 78125*128 = 10000000
const int nb_rounds = 10000000;
const int nb_blocks = 78125;
unsigned char sha256_hash[SHA256_DIGEST_LENGTH];

map<int, vector<char>> consensus_evaluation(const char* block){

    bool isDataIsFile = true;
    map<int, vector<char>> hash_map;
    int i = 0;

    while(i < nb_blocks) {

        vector<char> hash_vector;

        if (isDataIsFile) {
            //only the first part is hashed (nb_rounds/nb_blocks)
            if (sha256_file_fun(block, sha256_hash, nb_rounds/nb_blocks, isDataIsFile) == 0) {

                // copy(sha256_hash, sha256_hash + SHA256_DIGEST_LENGTH, hash_value);

                // Adding the hash to hash_vector
                for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                    hash_vector.push_back(sha256_hash[i]);
                }

                /*
                // Display value of the hash in hex
                char *hex_string = showhex(reinterpret_cast<const uint8_t *>(sha256_hash), SHA256_DIGEST_LENGTH);
                printf("Hash at round %d : %s\n", i+1, hex_string);
                */

                //cout << "Raw hash of the file : " << sha256_hash << endl;

                /*
                cout << "Bin hash of the file : ";
                print_binary(reinterpret_cast<const uint8_t *>(sha256_hash), SHA256_DIGEST_LENGTH);
                cout << endl;
                */
                /*
                // Display data of hash_vector in hex
                cout << "Contents of hash_vector : ";
                for (char hash_byte: hash_vector) {
                    cout << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(hash_byte));
                }
                cout << endl;
                */
                /*
                // Affichage du premier élément ajouté à hash_vector
                cout << "First hash value pushed into hash_vector: ";
                cout << static_cast<int>(static_cast<uint8_t>(hash_vector[0])) << endl;
                */


            } else {
                cerr << "Error in the sha256 calcul of the block" << endl;
            }
        }
        // Won't hash n times the file rn but n times FROM the nb_rounds/nb_blocks ^th hash of the file (for the first loop), and so on
        else {
            if (hash_map.find(i-1) != hash_map.end()) {

                // Get the previous hash from dictionnary
                const vector<char>& previous_hash = hash_map[i-1];

                /*
                cout << "Contents of previous hash : ";
                for (char hash_byte: previous_hash) {
                    cout << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(hash_byte));
                }
                cout << endl;

                // Display value of the hash in hex
                char *hex_string = showhex(reinterpret_cast<const uint8_t *>(&previous_hash[0]), SHA256_DIGEST_LENGTH);
                printf("Hash %d of the file : %s\n", i-1, hex_string);
                */

                if (sha256_file_fun(&previous_hash[0], sha256_hash, nb_rounds/nb_blocks, isDataIsFile) == 0) {

                    /*
                    // Display value of the hash in hex
                    char *hex_string = showhex(reinterpret_cast<const uint8_t *>(sha256_hash), SHA256_DIGEST_LENGTH);
                    printf("Hash at round %d : %s\n", i+1, hex_string);
                    */

                    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
                        hash_vector.push_back(sha256_hash[i]);
                    }

                }
                else {
                    cerr << "Error in the sha256 calcul of the block" << endl;
                }
            } else{
                cerr << "Error, no previous hash calculated" << endl;
            }
        }

        // add the hash_vector to the map/dictionnary
        hash_map.insert({i, hash_vector});
        // We're no longer working with the file but with the hash
        isDataIsFile = false;
        i++;

    }
    return hash_map;
}

void display_op(map<int, vector<char>> hash_map){
    /*
    // Traverse the map/dictionnary with an iterator
    for(auto it = hash_map.begin(); it != hash_map.end(); ++it){
        cout << "Clé : " << it->first << ", Valeur : ";

        // Display each char (in hexa) in the vector associated to the good key
        for(char c : it->second){
            cout << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(c));
        }

        cout << endl;
    }
    printf("\n");
    */
    if (!hash_map.empty()) {
        auto last_it = --hash_map.end(); // Accéder à l'élément avant end() pour obtenir le dernier élément
        cout << "Last value from the last key (hex) : \n";
        cout << "key : " << last_it->first;
        cout << "\nvalue : ";
        for (char c : last_it->second) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(c));
        }
        cout << endl;
    }

    ofstream outfile("hash_map.txt");
    if (!outfile.is_open()) {
        cerr << "Err opening file" << endl;
        exit(1);
    }

    for(auto it = hash_map.begin(); it != hash_map.end(); ++it){
        outfile << "Key : " << it->first << ", Value : ";

        for(char c : it->second){
            outfile << hex << setw(2) << setfill('0') << static_cast<int>(static_cast<uint8_t>(c));
        }

        outfile << endl;
    }
    outfile.close();

}

// probably OPENMP part - each thread must check a value in the dictionnary
int consensus_verification(){

    return 0;
}


int main() {

    const char* block = "../blocks/new_blk03802.dat"; //just a Bitcoin block using here for the test
    map<int, vector<char>> hash_map = consensus_evaluation(block);

    display_op(hash_map);

    return 0;
}
