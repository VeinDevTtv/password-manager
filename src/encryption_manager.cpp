#include "encryption_manager.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/pkcs5.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

EncryptionManager::EncryptionManager() {
    ctx_ = EVP_CIPHER_CTX_new();
    if (!ctx_) {
        throw std::runtime_error("Failed to create cipher context");
    }
    
    // Initialize key and IV
    key_.resize(KEY_SIZE);
    iv_.resize(IV_SIZE);
}

EncryptionManager::~EncryptionManager() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(ctx_);
    }
}

bool EncryptionManager::setMasterPassword(const std::string& password) {
    masterPasswordHash_ = hashPassword(password);
    deriveKey(password);
    return true;
}

bool EncryptionManager::verifyMasterPassword(const std::string& password) const {
    return hashPassword(password) == masterPasswordHash_;
}

std::vector<unsigned char> EncryptionManager::encrypt(const std::string& plaintext) {
    if (!ctx_) {
        throw std::runtime_error("Cipher context not initialized");
    }
    
    // Generate random IV
    if (RAND_bytes(iv_.data(), IV_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random IV");
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx_, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1) {
        throw std::runtime_error("Failed to initialize encryption");
    }
    
    // Prepare output buffer
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len1 = 0, len2 = 0;
    
    // Encrypt
    if (EVP_EncryptUpdate(ctx_, ciphertext.data(), &len1,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         static_cast<int>(plaintext.size())) != 1) {
        throw std::runtime_error("Failed to encrypt data");
    }
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx_, ciphertext.data() + len1, &len2) != 1) {
        throw std::runtime_error("Failed to finalize encryption");
    }
    
    // Resize to actual length
    ciphertext.resize(len1 + len2);
    
    // Prepend IV to ciphertext
    ciphertext.insert(ciphertext.begin(), iv_.begin(), iv_.end());
    
    return ciphertext;
}

std::string EncryptionManager::decrypt(const std::vector<unsigned char>& ciphertext) {
    if (!ctx_) {
        throw std::runtime_error("Cipher context not initialized");
    }
    
    if (ciphertext.size() < IV_SIZE) {
        throw std::runtime_error("Invalid ciphertext size");
    }
    
    // Extract IV
    std::vector<unsigned char> iv(ciphertext.begin(), ciphertext.begin() + IV_SIZE);
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx_, EVP_aes_256_cbc(), nullptr, key_.data(), iv.data()) != 1) {
        throw std::runtime_error("Failed to initialize decryption");
    }
    
    // Prepare output buffer
    std::vector<unsigned char> plaintext(ciphertext.size() - IV_SIZE);
    int len1 = 0, len2 = 0;
    
    // Decrypt
    if (EVP_DecryptUpdate(ctx_, plaintext.data(), &len1,
                         ciphertext.data() + IV_SIZE,
                         static_cast<int>(ciphertext.size() - IV_SIZE)) != 1) {
        throw std::runtime_error("Failed to decrypt data");
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx_, plaintext.data() + len1, &len2) != 1) {
        throw std::runtime_error("Failed to finalize decryption");
    }
    
    // Resize to actual length
    plaintext.resize(len1 + len2);
    
    return std::string(plaintext.begin(), plaintext.end());
}

void EncryptionManager::deriveKey(const std::string& password) {
    // Generate random salt
    std::vector<unsigned char> salt(SALT_SIZE);
    if (RAND_bytes(salt.data(), SALT_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    
    // Derive key using PBKDF2
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                          salt.data(), SALT_SIZE,
                          ITERATIONS, EVP_sha256(),
                          KEY_SIZE, key_.data()) != 1) {
        throw std::runtime_error("Failed to derive key");
    }
}

std::string EncryptionManager::hashPassword(const std::string& password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
} 