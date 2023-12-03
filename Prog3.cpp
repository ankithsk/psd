#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>


// Function to generate a random session key
std::string generateSessionKey() {
    const int keyLength = 16; // 128 bits for AES-128
    unsigned char key[keyLength];
    RAND_bytes(key, keyLength);
    return std::string(reinterpret_cast<char*>(key), keyLength);
}

// Function to perform Diffie-Hellman key exchange
std::string performKeyExchange(RSA* publicKey, RSA* privateKey) {
    // Generate a random session key
    std::string sessionKey = generateSessionKey();

    // Encrypt the session key using the third-party's public key
    std::string encryptedSessionKey = rsaEncrypt(sessionKey, publicKey);

    // Decrypt the session key using our private key
    std::string decryptedSessionKey = rsaDecrypt(encryptedSessionKey, privateKey);

    // Ensure that the decrypted session key matches the original
    if (decryptedSessionKey != sessionKey) {
        std::cerr << "Error in key exchange" << std::endl;
        exit(EXIT_FAILURE);
    }

    return sessionKey;
}


// Function to set up AES encryption
std::string aesEncrypt(const std::string& plaintext, const std::string& key) {
    EVP_CIPHER_CTX* ctx;
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Error creating AES context");
        exit(EXIT_FAILURE);
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv) != 1) {
        perror("Error initializing AES encryption");
        exit(EXIT_FAILURE);
    }

    int ciphertextLen = 0;
    int plaintextLen = plaintext.length();
    unsigned char* ciphertext = new unsigned char[plaintextLen + AES_BLOCK_SIZE];

    if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLen, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintextLen) != 1) {
        perror("Error in AES encryption update");
        exit(EXIT_FAILURE);
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &finalLen) != 1) {
        perror("Error in finalizing AES encryption");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(ciphertext), ciphertextLen + finalLen);
}

// Function to set up AES decryption
std::string aesDecrypt(const std::string& ciphertext, const std::string& key) {
    EVP_CIPHER_CTX* ctx;
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Error creating AES context");
        exit(EXIT_FAILURE);
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), iv) != 1) {
        perror("Error initializing AES decryption");
        exit(EXIT_FAILURE);
    }

    int plaintextLen = 0;
    int ciphertextLen = ciphertext.length();
    unsigned char* plaintext = new unsigned char[ciphertextLen];

    if (EVP_DecryptUpdate(ctx, plaintext, &plaintextLen, reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertextLen) != 1) {
        perror("Error in AES decryption update");
        exit(EXIT_FAILURE);
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintextLen, &finalLen) != 1) {
        perror("Error in finalizing AES decryption");
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext), plaintextLen + finalLen);
}

// Function to set up a socket and wait for a connection
int setupServerSocket(int port) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Error creating server socket");
        exit(EXIT_FAILURE);
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, reinterpret_cast<struct sockaddr*>(&serverAddr), sizeof(serverAddr)) == -1) {
        perror("Error binding server socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 1) == -1) {
        perror("Error listening on server socket");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server is listening on port " << port << std::endl;

    int clientSocket = accept(serverSocket, nullptr, nullptr);
    if (clientSocket == -1) {
        perror("Error accepting connection");
        exit(EXIT_FAILURE);
    }

    close(serverSocket);
    return clientSocket;
}

int main() {
    // Load the public and private keys using the provided functions
    RSA* publicKey = loadPublicKey("pubkey.pem");
    RSA* privateKey = loadPrivateKey("privkey.pem");

    // Perform Diffie-Hellman key exchange
    std::string sessionKey = performKeyExchange(publicKey, privateKey);

    // Set up a server socket
    int port = 12345;
    int clientSocket = setupServerSocket(port);

    // Read and write encrypted messages using the session key
    while (true) {
        // Read encrypted message from the client
        char buffer[1024];
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) {
            perror("Error receiving data");
            break;
        }

        std::string encryptedMessage(buffer, bytesRead);

        // Decrypt the message using the session key
        std::string decryptedMessage = aesDecrypt(encryptedMessage, sessionKey);

        // Print the decrypted message
        std::cout << "Received message: " << decryptedMessage << std::endl;

        // Get a message from the user
        std::string sendMessage;
        std::cout << "Enter message to send: ";
        std::getline(std::cin, sendMessage);

        // Encrypt the message using the session key
        std::string encryptedSendMessage = aesEncrypt(sendMessage, sessionKey);

        // Send the encrypted message to the client
        ssize_t bytesSent = send(clientSocket, encryptedSendMessage.c_str(), encryptedSendMessage.length(), 0);
        if (bytesSent == -1) {
            perror("Error sending data");
            break;
        }
    }

    // Remember to free the allocated memory for the keys
    RSA_free(privateKey);
    RSA_free(publicKey);

    // Close the client socket
    close(clientSocket);

    return 0;
}
