#ifndef EWSD_BOOTID_H
#define EWSD_BOOTID_H

/*
 * Boot ID checker (C-only).
 *
 * - load_system_bootid_once(): reads /proc/sys/kernel/random/boot_id once
 *   and stores it internally.
 * - ewsd_bootid_check(): validates the received bootid string.
 *
 * Build option:
 *   -DEWSD_ENABLE_BOOTID=0  => boot_id feature disabled (checks always pass)
 */

void load_system_bootid_once(void);

/* Returns 1 when valid, 0 when missing/empty/mismatch. */
int ewsd_bootid_check(const char *recv_bootid);

#endif
