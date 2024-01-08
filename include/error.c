#include "error.h"

#include <stdio.h>
#include <stdlib.h>

void checkError(char* message){
    // Check if message contains "error", if so, show message and exit
    if (strstr(message, "error") != NULL) {
        // Get message after comma
        char* error_msg = strchr(message, ',') + 1;
        printf("ERROR: %s\n", error_msg);
        exit(EXIT_FAILURE);
    }
}