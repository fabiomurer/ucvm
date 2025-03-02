#include "utils.h"

#include <stdlib.h>
#include <stdio.h>

void panic(const char message[]) {
    perror(message);
    exit(EXIT_FAILURE);
}

