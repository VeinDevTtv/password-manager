#include "cli.hpp"
#include <iostream>
#include <filesystem>
#include <stdexcept>

namespace fs = std::filesystem;

int main() {
    try {
        // Create vault file path in user's home directory
        std::string vaultPath = (fs::path(getenv("USERPROFILE")) / ".password_vault.dat").string();
        
        // Create vault instance
        auto vault = std::make_shared<Vault>(vaultPath);
        
        // Create and run CLI
        CLI cli(vault);
        cli.run();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 