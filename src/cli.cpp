#include "cli.hpp"
#include <iostream>
#include <limits>
#include <random>
#include <chrono>
#include <thread>
#include <cstdlib>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

CLI::CLI(std::shared_ptr<Vault> vault)
    : vault_(vault)
    , lastActivity_(std::chrono::system_clock::now())
{
}

CLI::~CLI() {
    if (vault_) {
        vault_->lock();
    }
}

void CLI::run() {
    while (true) {
        checkAutoLogout();
        
        if (!vault_->isInitialized()) {
            std::cout << "Welcome to Password Manager!\n";
            std::cout << "Please set your master password: ";
            std::string masterPassword = getSecureInput("");
            
            if (!vault_->initialize(masterPassword)) {
                std::cout << "Failed to initialize vault. Please try again.\n";
                continue;
            }
        } else if (vault_->isLocked()) {
            std::cout << "Please enter your master password: ";
            std::string masterPassword = getSecureInput("");
            
            if (!vault_->unlock(masterPassword)) {
                std::cout << "Invalid master password. Please try again.\n";
                continue;
            }
        }
        
        showMainMenu();
    }
}

void CLI::showMainMenu() {
    while (true) {
        checkAutoLogout();
        clearScreen();
        
        std::cout << "\nPassword Manager Menu:\n";
        std::cout << "1. Add new credential\n";
        std::cout << "2. Search credentials\n";
        std::cout << "3. Edit credential\n";
        std::cout << "4. Delete credential\n";
        std::cout << "5. Generate password\n";
        std::cout << "6. Lock vault\n";
        std::cout << "7. Exit\n";
        std::cout << "Enter your choice: ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        
        switch (choice) {
            case 1:
                showAddCredentialMenu();
                break;
            case 2:
                showSearchMenu();
                break;
            case 3:
                showEditMenu();
                break;
            case 4:
                showDeleteMenu();
                break;
            case 5:
                showPasswordGeneratorMenu();
                break;
            case 6:
                vault_->lock();
                return;
            case 7:
                vault_->lock();
                std::exit(0);
            default:
                std::cout << "Invalid choice. Please try again.\n";
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void CLI::showAddCredentialMenu() {
    clearScreen();
    std::cout << "Add New Credential\n";
    
    std::cout << "Website: ";
    std::string website;
    std::getline(std::cin, website);
    
    std::cout << "Username: ";
    std::string username;
    std::getline(std::cin, username);
    
    std::cout << "Password: ";
    std::string password = getSecureInput("");
    
    CredentialEntry entry(website, username, password);
    if (vault_->addCredential(entry)) {
        std::cout << "Credential added successfully!\n";
    } else {
        std::cout << "Failed to add credential. Website may already exist.\n";
    }
    
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

void CLI::showSearchMenu() {
    clearScreen();
    std::cout << "Search Credentials\n";
    
    std::cout << "Enter search query: ";
    std::string query;
    std::getline(std::cin, query);
    
    auto results = vault_->searchCredentials(query);
    if (results.empty()) {
        std::cout << "No matching credentials found.\n";
    } else {
        std::cout << "\nMatching credentials:\n";
        for (const auto& entry : results) {
            std::cout << "Website: " << entry.getWebsite() << "\n";
            std::cout << "Username: " << entry.getUsername() << "\n";
            std::cout << "Password: " << entry.getPassword() << "\n";
            std::cout << "-------------------\n";
        }
    }
    
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

void CLI::showEditMenu() {
    clearScreen();
    std::cout << "Edit Credential\n";
    
    std::cout << "Enter website to edit: ";
    std::string website;
    std::getline(std::cin, website);
    
    auto results = vault_->searchCredentials(website);
    if (results.empty()) {
        std::cout << "Credential not found.\n";
    } else {
        const auto& entry = results[0];
        std::cout << "Current username: " << entry.getUsername() << "\n";
        std::cout << "New username (press Enter to keep current): ";
        std::string username;
        std::getline(std::cin, username);
        if (username.empty()) {
            username = entry.getUsername();
        }
        
        std::cout << "New password (press Enter to keep current): ";
        std::string password = getSecureInput("");
        if (password.empty()) {
            password = entry.getPassword();
        }
        
        CredentialEntry newEntry(website, username, password);
        if (vault_->updateCredential(website, newEntry)) {
            std::cout << "Credential updated successfully!\n";
        } else {
            std::cout << "Failed to update credential.\n";
        }
    }
    
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

void CLI::showDeleteMenu() {
    clearScreen();
    std::cout << "Delete Credential\n";
    
    std::cout << "Enter website to delete: ";
    std::string website;
    std::getline(std::cin, website);
    
    std::cout << "Are you sure you want to delete this credential? (y/n): ";
    char confirm;
    std::cin >> confirm;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (confirm == 'y' || confirm == 'Y') {
        if (vault_->deleteCredential(website)) {
            std::cout << "Credential deleted successfully!\n";
        } else {
            std::cout << "Failed to delete credential.\n";
        }
    }
    
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

void CLI::showPasswordGeneratorMenu() {
    clearScreen();
    std::cout << "Password Generator\n";
    
    std::cout << "Enter password length (8-64): ";
    int length;
    std::cin >> length;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (length < 8) length = 8;
    if (length > 64) length = 64;
    
    std::cout << "Include special characters? (y/n): ";
    char useSpecial;
    std::cin >> useSpecial;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    bool useSpecialChars = (useSpecial == 'y' || useSpecial == 'Y');
    
    std::string password = generatePassword(length, useSpecialChars);
    std::cout << "\nGenerated password: " << password << "\n";
    
    std::cout << "Password strength: " << calculatePasswordStrength(password) << "/100\n";
    
    std::cout << "Copy to clipboard? (y/n): ";
    char copy;
    std::cin >> copy;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    if (copy == 'y' || copy == 'Y') {
        if (copyToClipboard(password)) {
            std::cout << "Password copied to clipboard!\n";
        } else {
            std::cout << "Failed to copy to clipboard.\n";
        }
    }
    
    std::cout << "Press Enter to continue...";
    std::cin.get();
}

std::string CLI::getSecureInput(const std::string& prompt) {
    std::string input;
    
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT);
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif
    
    std::getline(std::cin, input);
    
#ifdef _WIN32
    SetConsoleMode(hStdin, mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    
    return input;
}

void CLI::clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void CLI::checkAutoLogout() {
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - lastActivity_);
    
    if (duration.count() >= AUTO_LOGOUT_MINUTES) {
        vault_->lock();
        clearScreen();
        std::cout << "Session timed out due to inactivity.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

void CLI::updateLastActivity() {
    lastActivity_ = std::chrono::system_clock::now();
}

std::string CLI::generatePassword(int length, bool useSpecialChars) {
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    
    std::string charset = lowercase + uppercase + digits;
    if (useSpecialChars) {
        charset += special;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.size() - 1);
    
    std::string password;
    password.reserve(length);
    
    // Ensure at least one character from each required set
    password += lowercase[dis(gen) % lowercase.size()];
    password += uppercase[dis(gen) % uppercase.size()];
    password += digits[dis(gen) % digits.size()];
    if (useSpecialChars) {
        password += special[dis(gen) % special.size()];
    }
    
    // Fill the rest randomly
    for (int i = password.size(); i < length; ++i) {
        password += charset[dis(gen)];
    }
    
    // Shuffle the password
    std::shuffle(password.begin(), password.end(), gen);
    
    return password;
}

int CLI::calculatePasswordStrength(const std::string& password) {
    int score = 0;
    
    // Length
    score += std::min(static_cast<int>(password.length()) * 4, 40);
    
    // Character types
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false;
    for (char c : password) {
        if (islower(c)) hasLower = true;
        else if (isupper(c)) hasUpper = true;
        else if (isdigit(c)) hasDigit = true;
        else hasSpecial = true;
    }
    
    if (hasLower) score += 10;
    if (hasUpper) score += 10;
    if (hasDigit) score += 10;
    if (hasSpecial) score += 10;
    
    // Entropy
    int uniqueChars = 0;
    std::vector<bool> seen(256, false);
    for (char c : password) {
        if (!seen[static_cast<unsigned char>(c)]) {
            seen[static_cast<unsigned char>(c)] = true;
            uniqueChars++;
        }
    }
    score += std::min(uniqueChars * 2, 20);
    
    return std::min(score, 100);
}

bool CLI::copyToClipboard(const std::string& text) {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) {
        return false;
    }
    
    if (!EmptyClipboard()) {
        CloseClipboard();
        return false;
    }
    
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) {
        CloseClipboard();
        return false;
    }
    
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (!pMem) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    
    memcpy(pMem, text.c_str(), text.size() + 1);
    GlobalUnlock(hMem);
    
    if (!SetClipboardData(CF_TEXT, hMem)) {
        GlobalFree(hMem);
        CloseClipboard();
        return false;
    }
    
    CloseClipboard();
    return true;
#else
    // For Linux, you would need to implement using xclip or similar
    return false;
#endif
}

void CLI::clearClipboard() {
#ifdef _WIN32
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }
#else
    // For Linux, you would need to implement using xclip or similar
#endif
} 