#ifndef EWSD_BLOCK_H
#define EWSD_BLOCK_H

#include <stdbool.h>
#include <stddef.h>

extern const char *blocked_paths[];
extern const size_t blocked_paths_count;

bool is_blocked_path(const char *path);

#endif
