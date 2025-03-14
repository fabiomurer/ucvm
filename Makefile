# Compiler and flags
CC = gcc

# Common flags for all builds
COMMON_CFLAGS = -Wall -Wextra -pedantic -std=c23

# Release build flags
RELEASE_CFLAGS = $(COMMON_CFLAGS) -Werror -O2
# Debug build flags with additional useful debugging options
DEBUG_CFLAGS = $(COMMON_CFLAGS) -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer

# Default to release build
BUILD_TYPE ?= release

ifeq ($(BUILD_TYPE),debug)
    CFLAGS = $(DEBUG_CFLAGS)
    BUILD_DIR = debug_build
    TARGET_SUFFIX = _debug
    # Add linking flags for sanitizers when in debug mode
    LDFLAGS += -fsanitize=address -fsanitize=undefined
else
    CFLAGS = $(RELEASE_CFLAGS)
    BUILD_DIR = release_build
    TARGET_SUFFIX =
endif

TARGET = ucvm$(TARGET_SUFFIX)

# Path to the GDB stub submodule
GDBSTUB_DIR = mini-gdbstub
GDBSTUB_BUILD_DIR = $(GDBSTUB_DIR)/build
GDBSTUB_LIB = $(GDBSTUB_BUILD_DIR)/libgdbstub.a

# Find all source files and create object file list
SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)

# Add the gdbstub library to linking flags
LDFLAGS += -L$(GDBSTUB_BUILD_DIR) -lgdbstub

# Include directory for gdbstub headers (if needed)
CFLAGS += -I$(GDBSTUB_DIR)/include

# Default target
all: $(GDBSTUB_LIB) $(BUILD_DIR) $(BUILD_DIR)/$(TARGET)

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Include dependency files if they exist
-include $(DEPS)

# Build the gdbstub library
$(GDBSTUB_LIB):
	$(MAKE) -C $(GDBSTUB_DIR)

# Link all object files into the target executable
$(BUILD_DIR)/$(TARGET): $(OBJS) $(GDBSTUB_LIB)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile C files to object files and generate dependency files
$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Debug build target
debug:
	$(MAKE) BUILD_TYPE=debug

# Release build target
release:
	$(MAKE) BUILD_TYPE=release

# Clean up build artifacts
clean:
	rm -rf $(BUILD_DIR) debug_build release_build
	$(MAKE) -C $(GDBSTUB_DIR) clean

# Rebuild everything from scratch
rebuild: clean all

# Debug rebuild
debug-rebuild: clean debug

# Release rebuild
release-rebuild: clean release

# Phony targets (not actual files)
.PHONY: all clean rebuild debug release debug-rebuild release-rebuild