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
# Build settings: zero first-party warnings at /W4 /WX (MSVC) or -Wall -Wextra.
# Flags are applied directly to first-party targets rather than
# through an interface library, so the exported package never depends on a
# private helper target.
# ---------------------------------------------------------------------------
function(dc_apply_build_settings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE
      /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP
      /wd4127  # conditional expression is constant (used deliberately in templates)
      /wd4324  # structure was padded due to alignment specifier
    )
    if(DC_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    target_compile_definitions(${target} PRIVATE
      _CRT_SECURE_NO_WARNINGS
      NOMINMAX
      WIN32_LEAN_AND_MEAN
    )
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if(DC_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(DC_ENABLE_ASAN)
    if(MSVC)
      # /DEBUG gives the ASan runtime symbols to report with.
      target_compile_options(${target} PRIVATE /fsanitize=address /Oy- /Zi)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO /DEBUG)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer -g)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

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
  src/net.cpp
  src/wire.cpp
  src/compiler.cpp
)
add_library(dc::core ALIAS dc_core)

target_include_directories(dc_core
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

dc_apply_build_settings(dc_core)
target_compile_features(dc_core PUBLIC cxx_std_20)
set_target_properties(dc_core PROPERTIES
  OUTPUT_NAME "distributedcompilation"
  POSITION_INDEPENDENT_CODE ON
  # The installed package must expose the same namespaced name that the build
  # tree uses, so a consumer links dc::core in both cases.
  EXPORT_NAME core
)

if(WIN32)
  target_link_libraries(dc_core PUBLIC ws2_32)
  if(MINGW)
    target_link_libraries(dc_core PUBLIC ws2_32)
  endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(dc_core PUBLIC Threads::Threads)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(DC_BUILD_TESTS)
  enable_testing()
  add_library(dc_test_support INTERFACE)
  target_include_directories(dc_test_support INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

  function(dc_add_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE dc::core dc_test_support)
    dc_apply_build_settings(${name})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/apps)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 900)
    if(ARGC GREATER 2)
      set_tests_properties(${name} PROPERTIES LABELS "${ARGV2}")
    endif()
  endfunction()

  dc_add_test(dc_tests_core tests/test_core.cpp unit)
  dc_add_test(dc_tests_property tests/test_property.cpp property)
  dc_add_test(dc_tests_concurrency tests/test_concurrency.cpp concurrency)
  dc_add_test(dc_tests_adversarial tests/test_adversarial.cpp adversarial)
endif()

# ---------------------------------------------------------------------------
# Examples and benchmarks
# ---------------------------------------------------------------------------
if(DC_BUILD_EXAMPLES)
  foreach(example example_identity example_transaction example_inspection)
    add_executable(dc_${example} examples/${example}.cpp)
    target_link_libraries(dc_${example} PRIVATE dc::core)
    dc_apply_build_settings(dc_${example})
    target_include_directories(dc_${example} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/apps)
  endforeach()
endif()

if(DC_BUILD_BENCHMARKS)
  add_executable(dc_bench benchmarks/dc_bench.cpp)
  target_link_libraries(dc_bench PRIVATE dc::core)
  dc_apply_build_settings(dc_bench)
  target_include_directories(dc_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/apps)
endif()

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
if(DC_BUILD_APPS)
  add_executable(dc_coordinator apps/dc_coordinator.cpp)
  add_executable(dc_worker apps/dc_worker.cpp)
  add_executable(dc_cli
    apps/dc_cli.cpp
    apps/dc_cli_proof.cpp
    apps/dc_cli_demo.cpp
    apps/dc_cli_cuda.cpp
  )

  foreach(app dc_coordinator dc_worker dc_cli)
    target_link_libraries(${app} PRIVATE dc::core)
    dc_apply_build_settings(${app})
    target_include_directories(${app} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/apps)
  endforeach()

  # -------------------------------------------------------------------------
  # Optional CUDA driver probe. The core library never depends on CUDA; this
  # executable is built only when a toolkit with the driver headers and import
  # library is present.
  # -------------------------------------------------------------------------
  set(DC_CUDA_TOOLKIT_ROOT "" CACHE PATH "CUDA toolkit root used for the optional driver probe")
  if(NOT DC_CUDA_TOOLKIT_ROOT)
    if(DEFINED ENV{CUDA_PATH} AND EXISTS "$ENV{CUDA_PATH}/include/cuda.h")
      set(DC_CUDA_TOOLKIT_ROOT "$ENV{CUDA_PATH}")
    else()
      file(GLOB _dc_cuda_candidates "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v*")
      list(SORT _dc_cuda_candidates)
      list(REVERSE _dc_cuda_candidates)
      foreach(_candidate IN LISTS _dc_cuda_candidates)
        if(EXISTS "${_candidate}/include/cuda.h")
          set(DC_CUDA_TOOLKIT_ROOT "${_candidate}")
          break()
        endif()
      endforeach()
    endif()
  endif()

  if(DC_WITH_CUDA STREQUAL "OFF")
    set(DC_CUDA_TOOLKIT_ROOT "")
  endif()

  if(DC_CUDA_TOOLKIT_ROOT AND EXISTS "${DC_CUDA_TOOLKIT_ROOT}/include/cuda.h")
    add_executable(dc_cuda_probe apps/dc_cuda_probe.cpp)
    target_include_directories(dc_cuda_probe PRIVATE "${DC_CUDA_TOOLKIT_ROOT}/include")
    target_link_directories(dc_cuda_probe PRIVATE "${DC_CUDA_TOOLKIT_ROOT}/lib/x64")
    target_link_libraries(dc_cuda_probe PRIVATE cuda)
    dc_apply_build_settings(dc_cuda_probe)
    message(STATUS "CUDA probe enabled with toolkit ${DC_CUDA_TOOLKIT_ROOT}")
  else()
    message(STATUS "CUDA probe disabled (no toolkit with cuda.h was found)")
  endif()
endif()
include(cmake/install-rules.cmake)
