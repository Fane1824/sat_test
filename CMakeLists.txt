cmake_minimum_required(VERSION 3.5)
project(ENCRYPT_APP C)

# Find gcrypt
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)

# Include mission-specific build definitions
include_directories(fsw/mission_inc)
include_directories(fsw/platform_inc)
include_directories(${GCRYPT_INCLUDE_DIRS})

# Include app-specific directories
include_directories(fsw/src)
include_directories(fsw/inc)

# Source files for the cFS application
set(SOURCES
    fsw/src/encrypt_app.c
)

# Create the app module
add_cfe_app(encrypt_app ${SOURCES})

# Link against libgcrypt
target_link_libraries(encrypt_app ${GCRYPT_LIBRARIES})