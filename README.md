# Password Manager

A secure, terminal-based password manager written in C++17 that stores user credentials in an encrypted local file.

## Features

- 🔐 Master password protection with SHA-256 hashing
- 🔒 AES encryption for all stored credentials
- 📝 CRUD operations for managing credentials
- 🔍 Search functionality
- 📋 Clipboard support for password copying
- 🔑 Password generator
- 📊 Password strength checker
- ⏱️ Auto logout after inactivity
- 📝 Access attempt logging

## Requirements

- C++17 compatible compiler
- CMake 3.10 or higher
- OpenSSL development libraries
- Thread support

## Building

```bash
# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .
```

## Usage

1. First run:
   - The program will prompt you to set a master password
   - This password will be used to encrypt/decrypt your credentials

2. Subsequent runs:
   - Enter your master password to access the vault
   - Use the menu-driven interface to manage your credentials

## Security Features

- All passwords are encrypted using AES-256
- Master password is hashed using SHA-256
- Secure key derivation using PBKDF2
- Secure password input (no echo)
- Automatic screen clearing after logout
- Access attempt logging

## Project Structure

```
.
├── CMakeLists.txt
├── README.md
├── include/
│   ├── vault.hpp
│   ├── encryption_manager.hpp
│   ├── cli.hpp
│   └── credential_entry.hpp
└── src/
    ├── main.cpp
    ├── vault.cpp
    ├── encryption_manager.cpp
    ├── cli.cpp
    └── credential_entry.cpp
```

## Dependencies

- OpenSSL: For cryptographic operations
- Standard C++ Library: For core functionality
- Platform-specific APIs: For clipboard and terminal operations

## License

MIT License 