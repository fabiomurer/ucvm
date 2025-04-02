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
file(GLOB SOURCES "src/*.c")

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

# Print build type
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")