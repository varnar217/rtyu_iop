SOLUTION_DIR=..
PROJECT_DIR=$(SOLUTION_DIR)/GlobalLib

COMPILER=g++

# Release, Debug or Profile
BUILD_CFG=Release

# Release
ifeq ($(BUILD_CFG),Release)
  COMPILER_FLAGS=-std=c++17 -O3 -fsigned-char -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
  BUILD_DIR=$(SOLUTION_DIR)/build-linux-Release
endif

# Debug
ifeq ($(BUILD_CFG),Debug)
  COMPILER_FLAGS=-std=c++17 -g -fsigned-char -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
  BUILD_DIR=$(SOLUTION_DIR)/build-linux-Debug
endif

# Profile
ifeq ($(BUILD_CFG),Profile)
  COMPILER_FLAGS=-std=c++17 -pg -Og -fsigned-char -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
  BUILD_DIR=$(SOLUTION_DIR)/build-linux-Profile
endif

