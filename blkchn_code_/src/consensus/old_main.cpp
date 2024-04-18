#include <string>
#include <stdio.h>
#include <iostream>
#include <stdbool.h>
#include <cstdio>

#define path "../VDF/pq-vdf-isogeny/VDF.sage"
#define ld_bool "-ld True"
#define vf_bool "-vf True"

using namespace std;


void LeaderVDF(){
    string command = "sage " + string(path) + " " + string(ld_bool);
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        cerr << "error opening sage file !" << endl;
    }
    char buffer[128];
    string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);

    cout << "Sage calculation result: " << result << endl;
}

void VerifyVDF(){
    string command = "sage " + string(path) + " " + string(vf_bool);
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        cerr << "error opening sage file !" << endl;
    }
    char buffer[128];
    string verification = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            verification += buffer;
    }
    pclose(pipe);

    cout << "Sage verification result: " << verification << endl;
}

int main(){

    // executes the setup and evaluation, and stock the result in leader_result.sage
    LeaderVDF();

    // executes the verification with result in leader_result.sage
    VerifyVDF();
    return 0;
}

int hex_to_int(hex_value){
    int n = stoi(hex_value, 0, 16);
    return n;
}