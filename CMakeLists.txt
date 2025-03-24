cmake_minimum_required(VERSION 3.5)
project(ENCRYPT_APP C)

# Include app-specific directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

# Add libgcrypt dependency
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)
include_directories(${GCRYPT_INCLUDE_DIRS})

# Source files for the cFS application
set(ENCRYPT_APP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt_app.c
)

# Create the app module
add_cfe_app(encrypt_app ${ENCRYPT_APP_SOURCES})

# Link against libgcrypt
target_link_libraries(encrypt_app ${GCRYPT_LIBRARIES})

# Disable building the ground station for now
# We'll only build the cFS app component
# add_executable(ground_station ${CMAKE_CURRENT_SOURCE_DIR}/src/ground_station.c)
# target_link_libraries(ground_station ${GCRYPT_LIBRARIES} osal cfe-core)