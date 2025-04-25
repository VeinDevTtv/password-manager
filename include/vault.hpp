#pragma once

#include "credential_entry.hpp"
#include "encryption_manager.hpp"
#include <vector>
#include <string>
#include <memory>
#include <mutex>

class Vault {
public:
    Vault(const std::string& vaultPath);
    ~Vault();

    // Vault operations
    bool initialize(const std::string& masterPassword);
    bool load(const std::string& masterPassword);
    bool save() const;
    
    // CRUD operations
    bool addCredential(const CredentialEntry& entry);
    bool updateCredential(const std::string& website, const CredentialEntry& newEntry);
    bool deleteCredential(const std::string& website);
    std::vector<CredentialEntry> searchCredentials(const std::string& query) const;
    
    // Access control
    bool isInitialized() const { return initialized_; }
    bool isLocked() const { return locked_; }
    void lock();
    bool unlock(const std::string& masterPassword);
    
private:
    std::string vaultPath_;
    std::vector<CredentialEntry> credentials_;
    std::unique_ptr<EncryptionManager> encryptionManager_;
    bool initialized_;
    bool locked_;
    mutable std::mutex mutex_;
    
    // Helper methods
    bool readVaultFile();
    bool writeVaultFile() const;
    void clearCredentials();
}; 