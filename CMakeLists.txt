cmake_minimum_required(VERSION 3.20)

project(DistributedCompilation
  VERSION 1.0.0
  DESCRIPTION "Open-source, vendor-neutral C++20 runtime for governing distributed compilation"
  HOMEPAGE_URL "https://github.com/pngen/Distributed-Compilation"
  LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(DC_BUILD_APPS "Build the coordinator, worker and CLI executables" ON)
option(DC_BUILD_TESTS "Build the test suites" ON)
option(DC_BUILD_EXAMPLES "Build the runnable examples" ON)
option(DC_BUILD_BENCHMARKS "Build the benchmark harness" ON)
option(DC_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(DC_ENABLE_ASAN "Build with AddressSanitizer" OFF)
set(DC_WITH_CUDA "AUTO" CACHE STRING "Build the optional CUDA driver probe (AUTO/ON/OFF)")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Warnings: zero first-party warnings at /W4 /WX (MSVC) or -Wall -Wextra (GCC/Clang)
# ---------------------------------------------------------------------------
add_library(dc_warnings INTERFACE)
if(MSVC)
  target_compile_options(dc_warnings INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP
    /wd4127  # conditional expression is constant (used deliberately in templates)
    /wd4324  # structure was padded due to alignment specifier
  )
  if(DC_WARNINGS_AS_ERRORS)
    target_compile_options(dc_warnings INTERFACE /WX)
  endif()
  target_compile_definitions(dc_warnings INTERFACE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
  )
else()
  target_compile_options(dc_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(DC_WARNINGS_AS_ERRORS)
    target_compile_options(dc_warnings INTERFACE -Werror)
  endif()
endif()

if(DC_ENABLE_ASAN)
  if(MSVC)
    target_compile_options(dc_warnings INTERFACE /fsanitize=address /Oy- /Zi)
    target_link_options(dc_warnings INTERFACE /INCREMENTAL:NO)
  else()
    target_compile_options(dc_warnings INTERFACE -fsanitize=address -fno-omit-frame-pointer -g)
    target_link_options(dc_warnings INTERFACE -fsanitize=address)
  endif()
endif()

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
add_library(dc_core STATIC
  src/digest.cpp
  src/types.cpp
  src/identity.cpp
  src/canonical.cpp
  src/model.cpp
  src/runtime.cpp
  src/codec.cpp
  src/persistence.cpp
  src/process.cpp
  src/validate.cpp
  src/state_codec.cpp
  src/coordinator.cpp
  src/coordinator_tx.cpp
)
add_library(dc::core ALIAS dc_core)

target_include_directories(dc_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(dc_core PRIVATE dc_warnings)
target_compile_features(dc_core PUBLIC cxx_std_20)
set_target_properties(dc_core PROPERTIES
  OUTPUT_NAME "distributedcompilation"
  POSITION_INDEPENDENT_CODE ON
)

if(WIN32)
  target_link_libraries(dc_core PUBLIC ws2_32)
  if(MINGW)
    target_link_libraries(dc_core PUBLIC ws2_32)
  endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(dc_core PUBLIC Threads::Threads)
