#include "ewsd_event.h"

#include <stdio.h>
#include <string.h>

#include <json-c/json.h>
#include <libwebsockets.h>

#include "ewsd_common.h"
#include "ewsd_log.h"

void send_error_to_client(struct lws *wsi, int error_code, const char *error_message) 
{
    struct json_object *response_obj = json_object_new_object();
    struct json_object *error_obj = json_object_new_object();

    json_object_object_add(error_obj, "code", json_object_new_int(error_code));
    json_object_object_add(error_obj, "message", json_object_new_string(error_message));
    json_object_object_add(response_obj, "error", error_obj);

    json_object_object_add(response_obj, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(response_obj, "id", NULL); // NULL when ID is not exist

    // crate json
    const char *response_str = json_object_to_json_string(response_obj);

    // ready for websocket buffer
    unsigned char buffer[LWS_PRE + LWS_BUFFER_SIZE];
    size_t response_len = strlen(response_str);
    memcpy(&buffer[LWS_PRE], response_str, response_len);

    // send websocket
    int ret = lws_write(wsi, &buffer[LWS_PRE], response_len, LWS_WRITE_TEXT);
    if (ret < 0) {
        log_to_file("Failed to send error message to WebSocket client.");
    }

    json_object_put(response_obj);
}
