#include <string>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// Function to load private key from privkey.pem
RSA* loadPrivateKey(const char* key_file) {
    FILE* fp = fopen(key_file, "rb");
    if (!fp) {
        std::cerr << "Error opening private key file" << std::endl;
        exit(EXIT_FAILURE);
    }
    RSA* rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        std::cerr << "Error loading private key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return rsa;
}

// Function to load public key from pubkey.pem
RSA* loadPublicKey(const char* key_file) {
    FILE* fp = fopen(key_file, "rb");
    if (!fp) {
        std::cerr << "Error opening public key file" << std::endl;
        exit(EXIT_FAILURE);
    }
    RSA* rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        std::cerr << "Error loading public key" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return rsa;
}

// Function to perform RSA encryption
std::string rsaEncrypt(const std::string& plaintext, RSA* publicKey) {
    int rsaLen = RSA_size(publicKey);
    unsigned char* ciphertext = new unsigned char[rsaLen];
    int result = RSA_public_encrypt(plaintext.length(), reinterpret_cast<const unsigned char*>(plaintext.c_str()), ciphertext, publicKey, RSA_PKCS1_PADDING);
    if (result == -1) {
        // Handle encryption error
        ERR_load_crypto_strings();
        char errBuf[130];
        ERR_error_string(ERR_get_error(), errBuf);
        std::cerr << "RSA encryption error: " << errBuf << std::endl;
        delete[] ciphertext;
        return "";
    }
    std::string encryptedText(reinterpret_cast<char*>(ciphertext), result);
    delete[] ciphertext;
    return encryptedText;
}

// Function to perform RSA decryption
std::string rsaDecrypt(const std::string& ciphertext, RSA* privateKey) {
    int rsaLen = RSA_size(privateKey);
    unsigned char* plaintext = new unsigned char[rsaLen];
    int result = RSA_private_decrypt(ciphertext.length(), reinterpret_cast<const unsigned char*>(ciphertext.c_str()), plaintext, privateKey, RSA_PKCS1_PADDING);
    if (result == -1) {
        // Handle decryption error
        ERR_load_crypto_strings();
        char errBuf[130];
        ERR_error_string(ERR_get_error(), errBuf);
        std::cerr << "RSA decryption error: " << errBuf << std::endl;
        delete[] plaintext;
        return "";
    }
    std::string decryptedText(reinterpret_cast<char*>(plaintext), result);
    delete[] plaintext;
    return decryptedText;
}

int main() {
    // Load the public and private keys using the provided functions
    RSA* publicKey = loadPublicKey("pubkey.pem");
    RSA* privateKey = loadPrivateKey("privkey.pem");

    std::string plaintext = "Hello, this is a secret message!";
    std::string encrypted = rsaEncrypt(plaintext, publicKey);
    std::cout << "Encrypted message: " << encrypted << std::endl;

    std::string decrypted = rsaDecrypt(encrypted, privateKey);
    std::cout << "Decrypted message: " << decrypted << std::endl;

    // Remember to free the allocated memory for the keys
    RSA_free(privateKey);
    RSA_free(publicKey);

    return 0;
}