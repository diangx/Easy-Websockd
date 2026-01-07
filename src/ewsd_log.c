#include "ewsd_log.h"

#include <stdio.h>
#include <time.h>

extern const char *LOG_FILE;

void log_to_file(const char *message) {
    if (!LOG_FILE) return;

    FILE *file = fopen(LOG_FILE, "a");
    if (file) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", localtime(&now));
        fprintf(file, "[%s] %s\n", timestamp, message);
        fclose(file);
    } else {
        fprintf(stderr, "Failed to open log file: %s\n", LOG_FILE);
    }
}
