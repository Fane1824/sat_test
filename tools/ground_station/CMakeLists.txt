cmake_minimum_required(VERSION 3.5)
project(ground_station C)

# Add libgcrypt dependency
find_package(PkgConfig REQUIRED)
pkg_check_modules(GCRYPT REQUIRED libgcrypt)
include_directories(${GCRYPT_INCLUDE_DIRS})

# Add the executable
add_executable(ground_station main.c)

# Link against libgcrypt
target_link_libraries(ground_station ${GCRYPT_LIBRARIES})