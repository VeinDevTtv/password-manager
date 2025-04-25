cmake_minimum_required(VERSION 3.10)
project(PasswordManager VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Add source files
set(SOURCES
    src/main.cpp
    src/vault.cpp
    src/encryption_manager.cpp
    src/cli.cpp
    src/credential_entry.cpp
)

# Add header files
set(HEADERS
    include/vault.hpp
    include/encryption_manager.hpp
    include/cli.hpp
    include/credential_entry.hpp
)

# Create executable
add_executable(password_manager ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(password_manager PRIVATE include)

# Link libraries
target_link_libraries(password_manager PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Set compiler warnings
if(MSVC)
    target_compile_options(password_manager PRIVATE /W4)
else()
    target_compile_options(password_manager PRIVATE -Wall -Wextra -Wpedantic)
endif() 