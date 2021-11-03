SOLUTION_DIR=..
PROJECT_DIR=$(SOLUTION_DIR)/SendMixedPcapApp
GLOBALLIB_DIR=$(SOLUTION_DIR)/GlobalLib
LIBPCAP_DIR=$(SOLUTION_DIR)/../../vendors/libpcap/libpcap-1.10.1
HTTPLIB_DIR=$(SOLUTION_DIR)/../../vendors/cpp-httplib/cpp-httplib-0.9.5
RESTINIO_DIR=$(SOLUTION_DIR)/../../vendors/restinio/restinio-v.0.6.13/dev
NLOHMANN_DIR=$(SOLUTION_DIR)/../../vendors/json/nlohmann/json-3.10.2
RAPIDJSON_DIR=$(SOLUTION_DIR)/../../vendors/json/rapidjson/rapidjson-1.1.0

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

PKGCONF=pkg-config
COMPILER_FLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LINKER_FLAGS += $(shell $(PKGCONF) --libs libdpdk)