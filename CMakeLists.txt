###############################################################################
# CMakeLists.txt
#
# PQC Benchmark Suite for XenevaOS
# Stage 1 — C++ Benchmark Engine
#
# Build system for post-quantum cryptography benchmarks using OpenSSL 3.x.
# Each experiment is compiled as a standalone executable.
###############################################################################

cmake_minimum_required(VERSION 3.16)

project(PQC_Benchmark_Suite
    VERSION 1.0.0
    DESCRIPTION "Post-Quantum Cryptography Benchmark Suite for XenevaOS"
    LANGUAGES CXX
)

# ---------------------------------------------------------------------------
# Compiler settings
# ---------------------------------------------------------------------------

# Prefer Clang++ when available, fallback to GCC
find_program(CLANGXX_PATH clang++)
if(CLANGXX_PATH)
    set(CMAKE_CXX_COMPILER ${CLANGXX_PATH})
else()
    set(CMAKE_CXX_COMPILER "g++")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Base compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -fomit-frame-pointer")

# Optimization profiles
set(CMAKE_CXX_FLAGS_RELEASE_O2 "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE_O3 "-O3 -DNDEBUG")

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release_O3 CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release_O2" "Release_O3")

# Inject optimization flags into C++
add_compile_definitions(OPT_FLAGS="${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE}}")
add_compile_definitions(COMPILER_ID="${CMAKE_CXX_COMPILER_ID}")

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

if(OPENSSL_VERSION VERSION_LESS "3.5")
    message(WARNING
        "OpenSSL ${OPENSSL_VERSION} detected. "
        "ML-KEM-768 and ML-DSA-65 require OpenSSL >= 3.5. "
        "Benchmarks using PQC algorithms may fail at runtime."
    )
endif()

message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

# ---------------------------------------------------------------------------
# Common include directory
# ---------------------------------------------------------------------------
set(COMMON_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# Output directories — keep binaries tidy
# ---------------------------------------------------------------------------
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ---------------------------------------------------------------------------
# Helper macro: add an experiment executable
# ---------------------------------------------------------------------------
macro(add_experiment NAME EXPERIMENT_DIR)
    file(GLOB _SRC "${EXPERIMENT_DIR}/*.cpp")
    add_executable(${NAME} ${_SRC})
    target_include_directories(${NAME} PRIVATE
        ${COMMON_INCLUDE_DIR}
        ${EXPERIMENT_DIR}
    )
    target_link_libraries(${NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endmacro()

# ---------------------------------------------------------------------------
# Experiment 1: ECDH P-256 vs ML-KEM-768
# ---------------------------------------------------------------------------
add_experiment(bench_ecdh_vs_mlkem
    ${CMAKE_SOURCE_DIR}/experiments/ecdh_vs_mlkem
)

# ---------------------------------------------------------------------------
# Results directory (created at build time so executables can write there)
# ---------------------------------------------------------------------------
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/results)

# ---------------------------------------------------------------------------
# Future experiments (uncomment as implemented)
# ---------------------------------------------------------------------------
add_experiment(bench_rsa_vs_mldsa
    ${CMAKE_SOURCE_DIR}/experiments/rsa_vs_mldsa)
#
add_experiment(bench_secure_boot
    ${CMAKE_SOURCE_DIR}/experiments/secure_boot)
#
add_experiment(bench_package_verify
    ${CMAKE_SOURCE_DIR}/experiments/package_verify)
#
add_experiment(bench_secure_ipc
    ${CMAKE_SOURCE_DIR}/experiments/secure_ipc)
