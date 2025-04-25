#pragma once

#include "vault.hpp"
#include <string>
#include <memory>
#include <chrono>

class CLI {
public:
    CLI(std::shared_ptr<Vault> vault);
    ~CLI();

    // Main interface
    void run();
    
private:
    std::shared_ptr<Vault> vault_;
    std::chrono::system_clock::time_point lastActivity_;
    static constexpr int AUTO_LOGOUT_MINUTES = 5;
    
    // Menu options
    void showMainMenu();
    void showAddCredentialMenu();
    void showSearchMenu();
    void showEditMenu();
    void showDeleteMenu();
    void showPasswordGeneratorMenu();
    
    // Helper methods
    std::string getSecureInput(const std::string& prompt);
    void clearScreen();
    void checkAutoLogout();
    void updateLastActivity();
    
    // Password generation
    std::string generatePassword(int length, bool useSpecialChars);
    int calculatePasswordStrength(const std::string& password);
    
    // Clipboard operations
    bool copyToClipboard(const std::string& text);
    void clearClipboard();
}; 