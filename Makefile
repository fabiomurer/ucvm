# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -pedantic -g -std=c23
LDFLAGS =

TARGET = ucvm

# Find all source files and create object file list
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

# Default target
all: $(TARGET)

# Include dependency files if they exist
-include $(DEPS)

# Link all object files into the target executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile C files to object files and generate dependency files
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(DEPS) $(TARGET)

# Rebuild everything from scratch
rebuild: clean all

# Phony targets (not actual files)
.PHONY: all clean rebuild