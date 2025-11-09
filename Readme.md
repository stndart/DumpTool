# DLL PE Image Base Modifier

A tool for modifying the image base of DLLs and reconstructing their Import Address Table (IAT). Example iat.csv is given for a certain .dll.

## Features

- **Image Base Modification**: Change the base address of PE files
- **IAT Reconstruction**: Rebuild Import Address Tables after base modification

## Prerequisites

- Visual Studio 2022
- CMake 3.15+
- LIEF library (automatically handled by CMake)

## Build Instructions

### Command Line
```bash
# Configure with Visual Studio 2022 (Win32)
cmake -S . -B build -G "Visual Studio 17 2022" -A Win32

# Build Release configuration
cmake --build build --config Release
```

## Usage

Drop some .dll in the same folder as `dlltools.exe`, along with `iat.csv` and run.
