cmake_minimum_required(VERSION 3.5)
project(ENCRYPT_APP C)

# Include app-specific directories
include_directories(${ENCRYPT_APP_SOURCE_DIR}/fsw/src)
include_directories(${ENCRYPT_APP_SOURCE_DIR}/fsw/inc)

# Add libgcrypt dependency
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)
include_directories(${GCRYPT_INCLUDE_DIRS})

# Source files for the cFS application
set(ENCRYPT_APP_SOURCES
    src/encrypt_app.c
)

# Create the app module
add_cfe_app(encrypt_app ${ENCRYPT_APP_SOURCES})

# Link against libgcrypt
target_link_libraries(encrypt_app ${GCRYPT_LIBRARIES})

# Add a ground station simulator
add_executable(ground_station src/ground_station.c)
target_link_libraries(ground_station ${GCRYPT_LIBRARIES} osal cfe-core)