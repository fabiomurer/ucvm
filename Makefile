# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -pedantic -g -std=c23
LDFLAGS =

TARGET = ucvm

# Path to the GDB stub submodule
GDBSTUB_DIR = mini-gdbstub
GDBSTUB_BUILD_DIR = $(GDBSTUB_DIR)/build
GDBSTUB_LIB = $(GDBSTUB_BUILD_DIR)/libgdbstub.a

# Find all source files and create object file list
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

# Add the gdbstub library to linking flags
LDFLAGS += -L$(GDBSTUB_BUILD_DIR) -lgdbstub

# Include directory for gdbstub headers (if needed)
CFLAGS += -I$(GDBSTUB_DIR)/include

# Default target
all: $(GDBSTUB_LIB) $(TARGET)

# Include dependency files if they exist
-include $(DEPS)

# Build the gdbstub library
$(GDBSTUB_LIB):
	$(MAKE) -C $(GDBSTUB_DIR)

# Link all object files into the target executable
$(TARGET): $(OBJS) $(GDBSTUB_LIB)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile C files to object files and generate dependency files
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)
	$(MAKE) -C $(GDBSTUB_DIR) clean

# Rebuild everything from scratch
rebuild: clean all

# Phony targets (not actual files)
.PHONY: all clean rebuild