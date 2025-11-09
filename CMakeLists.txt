cmake_minimum_required(VERSION 3.15)
project(dlltools LANGUAGES CXX)

# Recommend C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# LIEF build config. Set the default options for LIEF's project setup
option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)

if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded" CACHE STRING "CRT option")
endif()

set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/LIEF")
if(EXISTS "${vendorLIEF_submodule_dir}")
  add_subdirectory("${vendorLIEF_submodule_dir}")
else()
  set(LIEF_GIT_URL "https://github.com/lief-project/LIEF.git")

  # LIEF's version to be used (can be 'main')
  set(LIEF_VERSION main)

  include(FetchContent)
  FetchContent_Declare(LIEF
    GIT_REPOSITORY  "${LIEF_GIT_URL}"
    GIT_TAG         ${LIEF_VERSION}
    # You may specify an existing LIEF source directory if you don't want to
    # download. Just comment out the above ``GIT_*`` commands and uncoment the
    # following ``SOURCE_DIR`` line
    #SOURCE_DIR      "${CMAKE_CURRENT_LIST_DIR}/../../.."
    )

  FetchContent_MakeAvailable(LIEF)
endif()

file(GLOB_RECURSE SOURCES src/*.cpp)

add_executable(dlltools
    ${SOURCES}
    # add a small main if you want, or compile these functions into a lib
)

# Link LIEF. The exported target is typically LIEF::LIEF (if installed with modern CMake)
target_link_libraries(dlltools PRIVATE LIEF::LIEF)

# Windows / MSVC specific options
if (MSVC)
  message(STATUS "MSVC detected: applying MSVC-friendly flags")
  target_compile_options(dlltools PRIVATE /W4 /permissive-)
  target_compile_definitions(dlltools PRIVATE _CRT_SECURE_NO_WARNINGS)
  # If you need to force use of 'cl' choose the appropriate CMake generator on command line:
  #   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
  # or for ninja+MSVC environment:
  #   cmake -S . -B build -G "Ninja" -T host=x64
endif()

# For non-MSVC (gcc/clang) add some sane flags
if (NOT MSVC)
  target_compile_options(dlltools PRIVATE -Wall -Wextra -Wpedantic)
endif()
