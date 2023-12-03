#include<string>
#include<iostream>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/err.h>
using namespace std;


int main(int argc, char** argv) {
 if (argc != 4) {
        cout<<"No command line arguements"<<endl;
        exit(EXIT_FAILURE);
    }
    const char* plaintext_file = argv[1];
    const char* third_party_public_key_file = argv[2];
    const char* your_private_key_file = argv[3];

}

