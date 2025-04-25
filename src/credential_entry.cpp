#include "credential_entry.hpp"
#include <sstream>
#include <iomanip>

CredentialEntry::CredentialEntry(const std::string& website, const std::string& username, const std::string& password)
    : website_(website)
    , username_(username)
    , password_(password)
    , lastModified_(std::chrono::system_clock::now())
{
}

void CredentialEntry::setWebsite(const std::string& website) {
    website_ = website;
    lastModified_ = std::chrono::system_clock::now();
}

void CredentialEntry::setUsername(const std::string& username) {
    username_ = username;
    lastModified_ = std::chrono::system_clock::now();
}

void CredentialEntry::setPassword(const std::string& password) {
    password_ = password;
    lastModified_ = std::chrono::system_clock::now();
}

std::string CredentialEntry::serialize() const {
    std::stringstream ss;
    ss << website_ << "|" << username_ << "|" << password_ << "|"
       << std::chrono::system_clock::to_time_t(lastModified_);
    return ss.str();
}

CredentialEntry CredentialEntry::deserialize(const std::string& data) {
    std::stringstream ss(data);
    std::string website, username, password, timestamp;
    
    std::getline(ss, website, '|');
    std::getline(ss, username, '|');
    std::getline(ss, password, '|');
    std::getline(ss, timestamp);
    
    CredentialEntry entry(website, username, password);
    entry.lastModified_ = std::chrono::system_clock::from_time_t(std::stoll(timestamp));
    
    return entry;
} 