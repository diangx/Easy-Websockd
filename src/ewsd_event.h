#ifndef EWSD_EVEMT_H
#define EWSD_EVENT_H

#include <libwebsockets.h>

void send_error_to_client(struct lws *wsi, int error_code, const char *error_message);

#endif
