# Makefile for FH - recursive source discovery, dep generation, debug/release
SHELL := /bin/sh

# Toolchain (override on command line, e.g. make CC=gcc MODE=release)
CC ?= clang
CXX ?= clang++
AR ?= ar rcs
RM ?= rm -rf

MODE ?= release        # debug or release
ifeq ($(MODE),release)
CFLAGS := -O2 -DNDEBUG
CXXFLAGS := -O2 -DNDEBUG
else
CFLAGS := -g -O0 -DDEBUG
CXXFLAGS := -g -O0 -DDEBUG
endif

COMMON_FLAGS := -Wall -Wextra -std=gnu11
COMMON_CXX := -Wall -Wextra -std=gnu++17

INCLUDE_DIRS := -I./src -I./include
CFLAGS += $(COMMON_FLAGS) $(INCLUDE_DIRS) -MMD -MP
CXXFLAGS += $(COMMON_CXX) $(INCLUDE_DIRS) -MMD -MP
LDFLAGS ?=
LDLIBS ?=

# Directories
SRC_DIR := src
OBJ_DIR := build/obj
BIN_DIR := build/bin
LIB_DIR := build/lib

# Discover sources
C_SRCS := $(shell find $(SRC_DIR) -type f -name '*.c')
CPP_SRCS := $(shell find $(SRC_DIR) -type f -name '*.cpp' -o -name '*.cc' -o -name '*.cxx')
SRCS := $(C_SRCS) $(CPP_SRCS)

# Map sources to object paths
OBJS := $(patsubst %.c,$(OBJ_DIR)/%.o,$(C_SRCS))
OBJS += $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(CPP_SRCS))
OBJS := $(sort $(OBJS))

# Final targets
TARGET := $(BIN_DIR)/fh
STATIC_LIB := $(LIB_DIR)/libfh.a

# Default target
.PHONY: all
all: $(TARGET) $(STATIC_LIB)

# Link executable
$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "Linking $@"
	$(CXX) $(filter %.o,$^) -o $@ $(LDFLAGS) $(LDLIBS)

# Create static library from all object files
$(STATIC_LIB): $(OBJS) | $(LIB_DIR)
	@echo "Creating static library $@"
	$(AR) $@ $(filter %.o,$^)

# Pattern rules for compiling C and C++
# Ensure object directory exists before compiling
$(OBJ_DIR)/%.o: %.c | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@echo "CC $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.cpp | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@echo "CXX $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.cc | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@echo "CXX $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.cxx | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@echo "CXX $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Create output directories
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Include generated dependency files
-include $(OBJS:.o=.d)

# Utility targets
.PHONY: clean distclean install rebuild mode-debug mode-release
clean:
	@echo "Cleaning build outputs"
	$(RM) $(OBJ_DIR)/*.o $(OBJ_DIR)/*/*.o $(BIN_DIR)/* $(LIB_DIR)/* || true

distclean: clean
	$(RM) build

rebuild: distclean all

# Switch build mode convenience
mode-debug:
	@$(MAKE) MODE=debug

mode-release:
	@$(MAKE) MODE=release

# Simple install (adjust prefix as needed)
PREFIX ?= /usr/local
install: all
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/lib
	install -m 0644 $(STATIC_LIB) $(DESTDIR)$(PREFIX)/lib/

# Phony listing
.PHONY: all clean distclean rebuild install mode-debug mode-release
