cmake_minimum_required(VERSION 3.12)
project(ucvm VERSION 0.1 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set C standard
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Define build types
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build" FORCE)
endif()


# Common compiler flags for ALL build types
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror -pedantic")

# Compiler flags for Debug and Release
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -DDEBUG -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")

# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/mini-gdbstub/include
)

# Collect source files
file(GLOB SOURCES "src/*.c" "src/vlinux/*.c")

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Build the submodule with its own Makefile
add_custom_target(gdbstub_lib
    COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR}/mini-gdbstub
    COMMENT "Building gdbstub library using its own Makefile"
)

# Add dependency on the custom target
add_dependencies(${PROJECT_NAME} gdbstub_lib)

# Link against the gdbstub library
target_link_libraries(${PROJECT_NAME} 
    ${CMAKE_CURRENT_SOURCE_DIR}/mini-gdbstub/build/libgdbstub.a
)

## linting

# Find required programs
find_program(CLANG_FORMAT "clang-format")
find_program(CLANG_TIDY "clang-tidy")

# Get all source files
file(GLOB_RECURSE ALL_SOURCE_FILES 
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/src/vlinux/*.c
    ${CMAKE_SOURCE_DIR}/include/*.h
    ${CMAKE_SOURCE_DIR}/include/vlinux/*.h
)

# Add target to run clang-format on all source files
add_custom_target(format
    COMMAND ${CLANG_FORMAT} -i ${ALL_SOURCE_FILES}
    COMMENT "Running clang-format on all source files"
    VERBATIM
)


# Create a custom target to create symbolic link to compilation database
add_custom_target(create_compile_commands_symlink
    COMMAND ${CMAKE_COMMAND} -E create_symlink
            ${CMAKE_BINARY_DIR}/compile_commands.json
            ${CMAKE_SOURCE_DIR}/compile_commands.json
    COMMENT "Creating symlink to compilation database at ${CMAKE_SOURCE_DIR}/compile_commands.json"
)

# Add target to run clang-tidy on all source files
add_custom_target(lint
    DEPENDS create_compile_commands_symlink
    COMMAND ${CLANG_TIDY} ${ALL_SOURCE_FILES}
    COMMENT "Running clang-tidy on all source file"
    VERBATIM
)

# Print build type
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")