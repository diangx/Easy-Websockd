#include "ewsd_block.h"
#include <string.h>

/* Blocked paths.
 * Example: const char *blocked_paths[] = { "file" };
 * "file" blocks everything in the `ubus -v list` output file.
 */
const char *blocked_paths[] = { "file" };
const size_t blocked_paths_count = sizeof(blocked_paths) / sizeof(blocked_paths[0]);

bool is_blocked_path(const char *path) {
    for (size_t i = 0; i < blocked_paths_count; i++) {
        if (strcmp(path, blocked_paths[i]) == 0) {
            return true;
        }
    }
    return false;
}
