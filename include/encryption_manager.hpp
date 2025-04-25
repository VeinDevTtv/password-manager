#pragma once

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

class EncryptionManager {
public:
    EncryptionManager();
    ~EncryptionManager();

    // Master password operations
    bool setMasterPassword(const std::string& password);
    bool verifyMasterPassword(const std::string& password) const;
    
    // Encryption/Decryption
    std::vector<unsigned char> encrypt(const std::string& plaintext);
    std::string decrypt(const std::vector<unsigned char>& ciphertext);
    
    // Key derivation
    void deriveKey(const std::string& password);
    
    // Password hashing
    static std::string hashPassword(const std::string& password);
    
private:
    // OpenSSL context
    EVP_CIPHER_CTX* ctx_;
    
    // Key and IV
    std::vector<unsigned char> key_;
    std::vector<unsigned char> iv_;
    
    // Master password hash
    std::string masterPasswordHash_;
    
    // Constants
    static constexpr int KEY_SIZE = 32;  // 256 bits
    static constexpr int IV_SIZE = 16;   // 128 bits
    static constexpr int SALT_SIZE = 16;
    static constexpr int ITERATIONS = 100000;
}; 