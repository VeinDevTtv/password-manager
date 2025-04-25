#pragma once

#include <string>
#include <chrono>

class CredentialEntry {
public:
    CredentialEntry() = default;
    CredentialEntry(const std::string& website, const std::string& username, const std::string& password);
    
    // Getters
    const std::string& getWebsite() const { return website_; }
    const std::string& getUsername() const { return username_; }
    const std::string& getPassword() const { return password_; }
    const std::chrono::system_clock::time_point& getLastModified() const { return lastModified_; }
    
    // Setters
    void setWebsite(const std::string& website);
    void setUsername(const std::string& username);
    void setPassword(const std::string& password);
    
    // Serialization
    std::string serialize() const;
    static CredentialEntry deserialize(const std::string& data);
    
private:
    std::string website_;
    std::string username_;
    std::string password_;
    std::chrono::system_clock::time_point lastModified_;
}; 