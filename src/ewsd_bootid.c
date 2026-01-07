#include "ewsd_bootid.h"

#include <stdio.h>
#include <string.h>

#include "ewsd_log.h"

/* Build option: -DEWSD_ENABLE_BOOTID=0/1 */
#ifndef EWSD_ENABLE_BOOTID
#define EWSD_ENABLE_BOOTID 1
#endif

#if EWSD_ENABLE_BOOTID

static char g_bootid_on_start[64] = {0};
static int  g_bootid_loaded = 0;

void load_system_bootid_once(void)
{
    if (g_bootid_loaded) {
        return;
    }

    FILE *fp = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (fp) {
        if (fgets(g_bootid_on_start, sizeof(g_bootid_on_start), fp)) {
            size_t n = strlen(g_bootid_on_start);
            if (n > 0 && g_bootid_on_start[n - 1] == '\n') {
                g_bootid_on_start[n - 1] = '\0';
            }
        }
        fclose(fp);
    }

    {
        char logmsg[128];
        snprintf(logmsg, sizeof(logmsg),
                 "[boot_id] loaded at service start: %s",
                 g_bootid_on_start);
        log_to_file(logmsg);
    }

    g_bootid_loaded = 1;
}

int ewsd_bootid_check(const char *recv_bootid)
{
    /* Be safe even if caller forgot to init */
    if (!g_bootid_loaded) {
        load_system_bootid_once();
    }

    if (!recv_bootid || recv_bootid[0] == '\0' ||
        strcmp(recv_bootid, g_bootid_on_start) != 0) {

        char logmsg[128];
        snprintf(logmsg, sizeof(logmsg),
                 "[boot_id] mismatch detected (recv:%s, system:%s)",
                 recv_bootid ? recv_bootid : "NULL",
                 g_bootid_on_start);
        log_to_file(logmsg);

        return 0;
    }

    return 1;
}

#else  /* EWSD_ENABLE_BOOTID == 0 */

void load_system_bootid_once(void) { }

int ewsd_bootid_check(const char *recv_bootid)
{
    (void)recv_bootid;
    return 1;
}

#endif
