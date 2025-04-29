#pragma once

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define WORDLEN sizeof(uintptr_t)

/**
 * Prints an error message with file and line information and exits the program
 * @param msg The error message to print
 */
#define PANIC(msg)                                                                    \
	do {                                                                          \
		(void)fprintf(stderr, "%s:%d: Error: %s\n", __FILE__, __LINE__, msg); \
		exit(EXIT_FAILURE);                                                   \
	} while (0)

/**
 * Prints an error message with file and line information along with the system
 * error description
 * @param msg The error message prefix
 */
#define PANIC_PERROR(msg)                                                                \
	do {                                                                             \
		(void)fprintf(stderr, "%s:%d: Error: %s: %s\n", __FILE__, __LINE__, msg, \
			      strerror(errno));                                          \
		exit(EXIT_FAILURE);                                                      \
	} while (0)

char *get_path_from_fd(int fd);
