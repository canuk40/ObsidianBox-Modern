cmake_minimum_required(VERSION 3.22.1)
project("obsidianboxmodern")

# =============================================================================
# ObsidianBox Modern Native Library
# Links Rust static libraries with JNI bridge to create unified native library
# =============================================================================

# Detect ABI and map to Rust output directory
# ANDROID_ABI is set by CMake Android toolchain
message(STATUS "Building for ABI: ${ANDROID_ABI}")

# Map Android ABI to Rust static library directory
if(${ANDROID_ABI} STREQUAL "arm64-v8a")
    set(RUST_ABI_DIR "arm64-v8a")
elseif(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    set(RUST_ABI_DIR "armeabi-v7a")
elseif(${ANDROID_ABI} STREQUAL "x86_64")
    set(RUST_ABI_DIR "x86_64")
elseif(${ANDROID_ABI} STREQUAL "x86")
    set(RUST_ABI_DIR "x86")
else()
    message(FATAL_ERROR "Unsupported ABI: ${ANDROID_ABI}")
endif()

# Paths to Rust libraries
set(RUST_STATIC_DIR "${CMAKE_SOURCE_DIR}/../../../../native/rust/target/android/${RUST_ABI_DIR}/release")
set(RUST_STATIC_LIB "${RUST_STATIC_DIR}/libobsidianbox_native.a")

# Check if static library exists
if(NOT EXISTS "${RUST_STATIC_LIB}")
    message(WARNING "Rust static library not found at: ${RUST_STATIC_LIB}")
    message(WARNING "Run 'native/rust/build-android.sh' to build Rust libraries first")
    message(WARNING "Building stub library without Rust FFI support")
    # Create a stub for development - the actual link will fail but allows CMake to configure
    set(RUST_LIB_AVAILABLE FALSE)
else()
    message(STATUS "Found Rust static library: ${RUST_STATIC_LIB}")
    add_library(obsidianbox_rust STATIC IMPORTED)
    set_target_properties(obsidianbox_rust PROPERTIES 
        IMPORTED_LOCATION "${RUST_STATIC_LIB}"
    )
    set(RUST_LIB_AVAILABLE TRUE)
endif()

# =============================================================================
# JNI Bridge Library
# Contains C++ JNI functions that wrap Rust FFI calls
# =============================================================================

add_library(obsidianboxmodern SHARED
    obsidianbox_bridge.cpp
    terminal_pty.cpp
)

# Include directories
target_include_directories(obsidianboxmodern PRIVATE
    ${CMAKE_SOURCE_DIR}
)

# Find Android libraries
find_library(log-lib log)
find_library(android-lib android)

# Link libraries
# Order matters: bridge first, then Rust static lib, then system libs
if(RUST_LIB_AVAILABLE)
    target_link_libraries(obsidianboxmodern
        obsidianbox_rust
        ${log-lib}
        ${android-lib}
    )
else()
    # Stub mode - only link system libraries
    target_link_libraries(obsidianboxmodern
        ${log-lib}
        ${android-lib}
    )
    # Define a macro to enable stub implementations
    target_compile_definitions(obsidianboxmodern PRIVATE OBSIDIANBOX_STUB_MODE=1)
endif()

# =============================================================================
# Compiler Settings
# =============================================================================

# Set C++ standard
set_target_properties(obsidianboxmodern PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Enable position-independent code for shared library
set_target_properties(obsidianboxmodern PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# 16 KB page size alignment for Android 15+ compatibility (Google Play requirement)
# This ensures LOAD segments are aligned at 16 KB boundaries
target_link_options(obsidianboxmodern PRIVATE
    "-Wl,-z,max-page-size=16384"
)

# Compiler warnings
target_compile_options(obsidianboxmodern PRIVATE
    -Wall
    -Wextra
    -Werror=return-type
)

# =============================================================================
# Debug/Release Configuration
# =============================================================================

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(obsidianboxmodern PRIVATE DEBUG=1)
    target_compile_options(obsidianboxmodern PRIVATE -g -O0)
else()
    target_compile_definitions(obsidianboxmodern PRIVATE NDEBUG=1)
    target_compile_options(obsidianboxmodern PRIVATE -O2)
endif()

message(STATUS "CMake configuration complete for ${PROJECT_NAME}")
