#!/bin/bash

# Check if a program path is provided
if [ $# -eq 0 ]; then
  echo "Usage: $0 <program_path>"
  exit 1
fi

# Get the program path
PROGRAM_PATH="$1"

# Extract program name (last part of the path without any directory)
PROGRAM_NAME=$(basename "$PROGRAM_PATH")

# Run the benchmark with hyperfine
echo "Running benchmark for $PROGRAM_PATH"
echo "Results will be saved to /tmp/$PROGRAM_NAME.md"
echo

hyperfine -i --export-markdown "/tmp/$PROGRAM_NAME.md" \
  "$PROGRAM_PATH" \
  "../../release/ucvm -- $PROGRAM_PATH" \
  "../../release/ucvm -p0 -- $PROGRAM_PATH" \
  "qemu-x86_64 $PROGRAM_PATH"