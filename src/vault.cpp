#include "vault.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <stdexcept>

Vault::Vault(const std::string& vaultPath)
    : vaultPath_(vaultPath)
    , encryptionManager_(std::make_unique<EncryptionManager>())
    , initialized_(false)
    , locked_(true)
{
}

Vault::~Vault() {
    if (!locked_) {
        save();
    }
}

bool Vault::initialize(const std::string& masterPassword) {
    if (initialized_) {
        return false;
    }
    
    if (!encryptionManager_->setMasterPassword(masterPassword)) {
        return false;
    }
    
    initialized_ = true;
    locked_ = false;
    return save();
}

bool Vault::load(const std::string& masterPassword) {
    if (!encryptionManager_->verifyMasterPassword(masterPassword)) {
        return false;
    }
    
    if (!readVaultFile()) {
        return false;
    }
    
    initialized_ = true;
    locked_ = false;
    return true;
}

bool Vault::save() const {
    if (locked_) {
        return false;
    }
    
    return writeVaultFile();
}

bool Vault::addCredential(const CredentialEntry& entry) {
    if (locked_) {
        return false;
    }
    
    // Check if entry already exists
    auto it = std::find_if(credentials_.begin(), credentials_.end(),
                          [&](const CredentialEntry& e) {
                              return e.getWebsite() == entry.getWebsite();
                          });
    
    if (it != credentials_.end()) {
        return false;
    }
    
    credentials_.push_back(entry);
    return save();
}

bool Vault::updateCredential(const std::string& website, const CredentialEntry& newEntry) {
    if (locked_) {
        return false;
    }
    
    auto it = std::find_if(credentials_.begin(), credentials_.end(),
                          [&](const CredentialEntry& e) {
                              return e.getWebsite() == website;
                          });
    
    if (it == credentials_.end()) {
        return false;
    }
    
    *it = newEntry;
    return save();
}

bool Vault::deleteCredential(const std::string& website) {
    if (locked_) {
        return false;
    }
    
    auto it = std::find_if(credentials_.begin(), credentials_.end(),
                          [&](const CredentialEntry& e) {
                              return e.getWebsite() == website;
                          });
    
    if (it == credentials_.end()) {
        return false;
    }
    
    credentials_.erase(it);
    return save();
}

std::vector<CredentialEntry> Vault::searchCredentials(const std::string& query) const {
    if (locked_) {
        return {};
    }
    
    std::vector<CredentialEntry> results;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    for (const auto& entry : credentials_) {
        std::string lowerWebsite = entry.getWebsite();
        std::transform(lowerWebsite.begin(), lowerWebsite.end(), lowerWebsite.begin(), ::tolower);
        
        if (lowerWebsite.find(lowerQuery) != std::string::npos) {
            results.push_back(entry);
        }
    }
    
    return results;
}

void Vault::lock() {
    if (!locked_) {
        save();
        clearCredentials();
        locked_ = true;
    }
}

bool Vault::unlock(const std::string& masterPassword) {
    if (!locked_) {
        return true;
    }
    
    return load(masterPassword);
}

bool Vault::readVaultFile() {
    std::ifstream file(vaultPath_, std::ios::binary);
    if (!file) {
        return false;
    }
    
    // Read encrypted data
    std::string encryptedData((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    
    if (encryptedData.empty()) {
        return true;
    }
    
    // Decrypt data
    std::string decryptedData = encryptionManager_->decrypt(
        std::vector<unsigned char>(encryptedData.begin(), encryptedData.end()));
    
    // Parse entries
    std::stringstream ss(decryptedData);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty()) {
            credentials_.push_back(CredentialEntry::deserialize(line));
        }
    }
    
    return true;
}

bool Vault::writeVaultFile() const {
    if (locked_) {
        return false;
    }
    
    // Serialize entries
    std::stringstream ss;
    for (const auto& entry : credentials_) {
        ss << entry.serialize() << "\n";
    }
    
    // Encrypt data
    std::vector<unsigned char> encryptedData = encryptionManager_->encrypt(ss.str());
    
    // Write to file
    std::ofstream file(vaultPath_, std::ios::binary);
    if (!file) {
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(encryptedData.data()),
               static_cast<std::streamsize>(encryptedData.size()));
    
    return true;
}

void Vault::clearCredentials() {
    credentials_.clear();
} 