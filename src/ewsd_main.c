#include <libwebsockets.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>

#include "ewsd_common.h"
#include "ewsd_log.h"
#include "ewsd_block.h"
#include "ewsd_bootid.h"
#include "ewsd_hash.h"
#include "ewsd_event.h"

int PORT = DEFAULT_PORT;
const char *LOG_FILE = DEFAULT_LOG_FILE;

typedef struct per_session_data {
    struct lws *wsi;                                    // WebSocket connection handle
    char client_ip[LWS_PATH_MAX];                       // client ip
    char client_sid[LWS_PATH_MAX];                      // client sid
    char client_perm[LWS_PATH_MAX];                     // client permission
    int values_stored;                                  // flag for array save (1 : save true, 0: save false)
    int pending_5005;
    int pending_ping;
    time_t last_pong;
} per_session_data_t;

typedef struct session_user_data {
    per_session_data_t *psds[MAX_WSI_COUNT];            // client management array
    int psd_count;                                      // curren client connected count
} session_user_data_t;

pthread_mutex_t lock;                                   // mutex
session_user_data_t session_user;

static volatile sig_atomic_t g_broadcast_5005 = 0;

static void on_sigusr1(int sig) {
    (void)sig;
    g_broadcast_5005 = 1;
}

static void trigger_broadcast_5005(void)
{
    pthread_mutex_lock(&lock);

    for (int i = 0; i < session_user.psd_count; ++i) {
        if (!session_user.psds[i] || !session_user.psds[i]->wsi)
            continue;

        session_user.psds[i]->pending_5005 = 1;
        lws_callback_on_writable(session_user.psds[i]->wsi);
    }

    pthread_mutex_unlock(&lock);
}

// ubus exec
char *execute_ubus_command(const char *path, const char *action, const char *msg) {
    static char result[LWS_BODY_MAX];
    result[0] = '\0';

    if (!path || !action || !msg) {
        log_to_file("execute_ubus_command: null arg");
        return NULL;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        log_to_file("pipe failed");
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        log_to_file("fork failed");
        close(pipefd[0]); close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        execlp("ubus", "ubus", "call", path, action, msg, (char *)NULL);

        const char *em = "exec ubus failed\n";
        write(STDOUT_FILENO, em, strlen(em));
        _exit(127);
    }

    close(pipefd[1]);

    ssize_t total = 0;
    while (total < (ssize_t)sizeof(result) - 1) {
        ssize_t r = read(pipefd[0], result + total, sizeof(result) - 1 - total);
        if (r > 0) {
            total += r;
            continue;
        }
        if (r == 0) break;
        if (errno == EINTR) continue;

        log_to_file("read failed from ubus");
        break;
    }
    result[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        log_to_file("waitpid failed");
    } else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        log_to_file("ubus call returned non-zero");
    }

    return result;
}

// Force remove websocket client. (just on board)
static void remove_psd_by_wsi(struct lws *target_wsi)
{
    if (!target_wsi) return;

    for (int i = 0; i < session_user.psd_count; ++i) {
        if (session_user.psds[i] && session_user.psds[i]->wsi == target_wsi) {

            char log_msg[LWS_PATH_MAX + 256];
            snprintf(log_msg, sizeof(log_msg),
                     "<<< FORCE REMOVE >>> INDEX: %d, IP: %s, Total clients: %d",
                     i,
                     session_user.psds[i]->client_ip,
                     session_user.psd_count - 1);
            log_to_file(log_msg);

            char ubus_query[1024];
            snprintf(ubus_query, sizeof(ubus_query),
                     "{\"ubus_rpc_session\":\"%s\"}", session_user.psds[i]->client_sid);
            execute_ubus_command("session", "destroy", ubus_query);

            free(session_user.psds[i]);
            session_user.psds[i] = NULL;

            for (int j = i; j < session_user.psd_count - 1; ++j) {
                session_user.psds[j] = session_user.psds[j + 1];
            }
            session_user.psds[session_user.psd_count - 1] = NULL;
            session_user.psd_count--;

            break;
        }
    }
}

// websocket callback
static int websocket_callback(struct lws *wsi, enum lws_callback_reasons reason,
                              void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            pthread_mutex_lock(&lock);

            if (session_user.psd_count >= MAX_WSI_COUNT) {
                pthread_mutex_unlock(&lock);
                log_to_file("Max clients reached, rejecting connection.");
                return -1;
            }

            per_session_data_t *psd = malloc(sizeof(per_session_data_t));
            if (!psd) {
                pthread_mutex_unlock(&lock);
                log_to_file("Failed to allocate memory for client.");
                return -1;
            }

            char client_ip[LWS_PATH_MAX] = {0};
            lws_hdr_copy(wsi, client_ip, sizeof(client_ip), WSI_TOKEN_HTTP_X_REAL_IP);
            if (strlen(client_ip) == 0) {
                strncpy(client_ip, "unknown", LWS_PATH_MAX);
            }
            strncpy(psd->client_ip, client_ip, LWS_PATH_MAX);
            psd->wsi = wsi;

            session_user.psds[session_user.psd_count++] = psd;
            session_user.psds[session_user.psd_count-1]->values_stored = 0;
            session_user.psds[session_user.psd_count-1]->pending_5005 = 0;
            session_user.psds[session_user.psd_count-1]->pending_ping = 0;
            session_user.psds[session_user.psd_count-1]->last_pong = time(NULL);

            char log_msg[LWS_PATH_MAX + 64];
            snprintf(log_msg, sizeof(log_msg), "< LWS_ESTABLISHED > INDEX : %d, IP: %s, Total clients: %d", session_user.psd_count-1, client_ip, session_user.psd_count);
            log_to_file(log_msg);

            pthread_mutex_unlock(&lock);
            lws_set_timer_usecs(wsi, LWS_PING_INTERVAL_SEC * LWS_USEC_PER_SEC);
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            static char message_buffer[LWS_BODY_MAX];
            static size_t message_len = 0;
            per_session_data_t *cur_psd = NULL;

            if (message_len + len < sizeof(message_buffer)) {
                memcpy(message_buffer + message_len, in, len);
                message_len += len;
            } else {
                log_to_file("Message buffer overflow, discarding data.");
                message_len = 0;
                break;
            }

            if (!lws_is_final_fragment(wsi)) {
                log_to_file("Message fragment received, waiting for the final fragment.");
                break;
            }

            message_buffer[message_len] = '\0';

            struct json_object *request = json_tokener_parse(message_buffer);
            if (!request) {
                log_to_file("Invalid JSON format.");
                message_len = 0;
                break;
            }

            struct json_object *method_obj=NULL, *params_obj=NULL, *hash_obj=NULL, *sid_obj=NULL, *bootid_obj=NULL;
            if (json_object_object_get_ex(request, "method", &method_obj) &&
                json_object_object_get_ex(request, "params", &params_obj) &&
                json_object_object_get_ex(request, "hash", &hash_obj) &&
                json_object_object_get_ex(params_obj, "sid", &sid_obj)) {

                json_object_object_get_ex(params_obj, "bootid", &bootid_obj);
                const char *bootid = bootid_obj ? json_object_get_string(bootid_obj) : NULL;
                const char *method = json_object_get_string(method_obj);
                const char *received_hash = json_object_get_string(hash_obj);
                const char *params_string = json_object_to_json_string_ext(params_obj, JSON_C_TO_STRING_PLAIN);

                int process_complete = 0;

                for (int i = 0; i < session_user.psd_count; i++) {
                    if (session_user.psds[i]->wsi == wsi) {
                        const char *sid = json_object_get_string(sid_obj);
                        if (!sid) { // return when sid is NULL
                            send_error_to_client(session_user.psds[i]->wsi, 5000, "session not found.");
                            json_object_put(request);
                            message_len = 0;
                            return -1;
                        }

                        char ubus_query[1024];
                        snprintf(ubus_query, sizeof(ubus_query), "{\"ubus_rpc_session\":\"%s\"}", sid);

                        char *result_sid = execute_ubus_command("session", "get", ubus_query);
                        char username_buf[LWS_PATH_MAX] = "unknown";

                        if (result_sid) {
                            struct json_object *root = json_tokener_parse(result_sid);
                            if (root) {
                                struct json_object *values, *username;
                                if (json_object_object_get_ex(root, "values", &values) &&
                                    json_object_object_get_ex(values, "username", &username) &&
                                    json_object_is_type(username, json_type_string)) {
                                    const char *username_str = json_object_get_string(username);
                                    if (username_str) {
                                        strncpy(username_buf, username_str, LWS_PATH_MAX - 1);
                                        username_buf[LWS_PATH_MAX - 1] = '\0';
                                    }
                                }
                                json_object_put(root);
                            }
                            free(result_sid);
                        }

                        if (strcmp(username_buf, "unknown") == 0) { // client session of username not exist (ubus call session get)
                            send_error_to_client(session_user.psds[i]->wsi, 5001, "username unknown.");
                            lws_set_timeout(session_user.psds[i]->wsi, PENDING_TIMEOUT_CLOSE_SEND, 1);
                        }
                        else if (session_user.psds[i]->values_stored) { // already exist client value
                            cur_psd = session_user.psds[i];
                            process_complete = 1;
                            continue;
                        }
                        else { // save client info
                            strncpy(session_user.psds[i]->client_sid, sid, LWS_PATH_MAX - 1);
                            session_user.psds[i]->client_sid[LWS_PATH_MAX - 1] = '\0';

                            strncpy(session_user.psds[i]->client_perm, username_buf, LWS_PATH_MAX - 1);
                            session_user.psds[i]->client_perm[LWS_PATH_MAX - 1] = '\0';

                            char log_msg_info_connect[LWS_PATH_MAX + 128];
                            snprintf(log_msg_info_connect, sizeof(log_msg_info_connect),
                                    "<< LWS_RECEIVE >> INDEX: %d, IP: %s, WSI: %p, SID: %s, PERM: %s",
                                    i,
                                    session_user.psds[i]->client_ip ? session_user.psds[i]->client_ip : "unknown",
                                    (void *)session_user.psds[i]->wsi,
                                    session_user.psds[i]->client_sid,
                                    session_user.psds[i]->client_perm);
                            log_to_file(log_msg_info_connect);

                            per_session_data_t *new_psd = session_user.psds[i];

                            for (int j = 0; j < session_user.psd_count; j++) {
                                if (i != j &&
                                    session_user.psds[j]->wsi != wsi &&
                                    strcmp(session_user.psds[j]->client_ip, new_psd->client_ip) != 0 &&
                                    strcmp(session_user.psds[j]->client_perm, new_psd->client_perm) == 0) {

                                    log_to_file("Other IP Client init.");

                                    struct lws *kick_wsi = session_user.psds[j]->wsi;
                                    send_error_to_client(kick_wsi, 5002, "other ip init. logout");
                                    remove_psd_by_wsi(kick_wsi);

                                    send_error_to_client(new_psd->wsi, 5003, "other ip init. login");

                                    break;
                                }
                            }

                            new_psd->values_stored = 1;
                            cur_psd = new_psd;
                            process_complete = 1;
                        }
                    }
                }

                if (process_complete) {
                    if (!verify_hash(params_string, received_hash)) {
                        log_to_file("Hash mismatch. Dropping message.");
                        json_object_put(request);
                        message_len = 0;
                        break;
                    }

                    if (!ewsd_bootid_check(bootid)) {
                        send_error_to_client(wsi, 5004, "boot_id mismatch.");
                        json_object_put(request);
                        message_len = 0;
                        break;
                    }

                    if (strcmp(method, "ubus") == 0) {
                        struct json_object *path_obj, *action_obj, *msg_obj;
                        if (json_object_object_get_ex(params_obj, "path", &path_obj) &&
                            json_object_object_get_ex(params_obj, "action", &action_obj)) {
                            const char *path = json_object_get_string(path_obj);
                            const char *action = json_object_get_string(action_obj);
                            const char *msg = "{}";
                            if (json_object_object_get_ex(params_obj, "msg", &msg_obj)) {
                                if (cur_psd && strlen(cur_psd->client_ip) > 0 && strcmp(cur_psd->client_ip, "unknown") != 0) {
                                    json_object_object_add(msg_obj, "ws_ip", json_object_new_string(cur_psd->client_ip));
                                }
                                msg = json_object_to_json_string(msg_obj);
                            }
                            char *result = execute_ubus_command(path, action, msg);
                            if (!result) {
                                log_to_file("Failed to execute ubus command or no response.");
                                break;
                            }

                            struct json_object *response_obj = json_tokener_parse(result);
                            if (!response_obj) {
                                response_obj = json_object_new_object();
                            }

                            struct json_object *response = json_object_new_object();
                            json_object_object_add(response, "jsonrpc", json_object_new_string("2.0"));

                            struct json_object *id_obj;
                            if (json_object_object_get_ex(request, "id", &id_obj)) {
                                json_object_object_add(response, "id", id_obj);
                            }
                            json_object_object_add(response, "result", response_obj);

                            const char *response_str = json_object_to_json_string(response);

                            const size_t response_len = strlen(response_str);
                            const unsigned char *data = (const unsigned char *)response_str;
                            size_t sent = 0;

                            while (sent < response_len) {
                                size_t chunk_size = (response_len - sent > LWS_BUFFER_SIZE) ? LWS_BUFFER_SIZE : (response_len - sent);
                                unsigned char buffer[LWS_PRE + LWS_BUFFER_SIZE];
                                memcpy(&buffer[LWS_PRE], data + sent, chunk_size);

                                int flags = (sent == 0) ? LWS_WRITE_TEXT : LWS_WRITE_CONTINUATION;
                                if (sent + chunk_size == response_len) {
                                    flags |= LWS_WRITE_NO_FIN == 0; // last fragment
                                } else {
                                    flags |= LWS_WRITE_NO_FIN;
                                }

                                if (lws_write(wsi, &buffer[LWS_PRE], chunk_size, flags) < 0) {
                                    log_to_file("Failed to send chunked response.");
                                    break;
                                }

                                sent += chunk_size;
                            }

                            json_object_put(response);
                        }
                    }
                }
            } else {
                log_to_file("Invalid JSON-RPC format.");
            }

            json_object_put(request);
            message_len = 0;
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            pthread_mutex_lock(&lock);

            for (int i = 0; i < session_user.psd_count; ++i) {
                if (session_user.psds[i] && session_user.psds[i]->wsi == wsi) {
                    if (session_user.psds[i]->pending_5005) {
                        session_user.psds[i]->pending_5005 = 0;
                        pthread_mutex_unlock(&lock);

                        send_error_to_client(wsi, 5005, "reboot-button pressed.");
                        return 0;
                    }
                    if (session_user.psds[i]->pending_ping) {
                        session_user.psds[i]->pending_ping = 0;
                        pthread_mutex_unlock(&lock);

                        unsigned char ping_buf[LWS_PRE + 1];
                        if (lws_write(wsi, &ping_buf[LWS_PRE], 0, LWS_WRITE_PING) < 0) {
                            log_to_file("Failed to send ping.");
                        }
                        return 0;
                    }
                    break;
                }
            }

            pthread_mutex_unlock(&lock);
            break;
        }

        case LWS_CALLBACK_TIMER: {
            pthread_mutex_lock(&lock);

            for (int i = 0; i < session_user.psd_count; ++i) {
                if (session_user.psds[i] && session_user.psds[i]->wsi == wsi) {
                    time_t now = time(NULL);
                    if ((now - session_user.psds[i]->last_pong) > LWS_PONG_TIMEOUT_SEC) {
                        char log_msg[LWS_PATH_MAX + 128];
                        snprintf(log_msg, sizeof(log_msg),
                                 "Ping timeout. Closing connection. IP: %s",
                                 session_user.psds[i]->client_ip);
                        log_to_file(log_msg);
                        pthread_mutex_unlock(&lock);
                        lws_set_timeout(wsi, PENDING_TIMEOUT_CLOSE_SEND, 1);
                        return 0;
                    }

                    session_user.psds[i]->pending_ping = 1;
                    lws_callback_on_writable(wsi);
                    break;
                }
            }

            pthread_mutex_unlock(&lock);
            lws_set_timer_usecs(wsi, LWS_PING_INTERVAL_SEC * LWS_USEC_PER_SEC);
            break;
        }

        case LWS_CALLBACK_RECEIVE_PONG: {
            pthread_mutex_lock(&lock);

            for (int i = 0; i < session_user.psd_count; ++i) {
                if (session_user.psds[i] && session_user.psds[i]->wsi == wsi) {
                    session_user.psds[i]->last_pong = time(NULL);
                    break;
                }
            }

            pthread_mutex_unlock(&lock);
            break;
        }

        case LWS_CALLBACK_CLOSED: {
            pthread_mutex_lock(&lock);

            for (int i = 0; i < session_user.psd_count; ++i) {
                if (session_user.psds[i]->wsi == wsi) {
                    char log_msg[LWS_PATH_MAX + 256];
                    snprintf(log_msg, sizeof(log_msg), "<<< LWS_CALLBACK_CLOSED >>> INDEX: %d, IP: %s, Total clients: %d", i, session_user.psds[i]->client_ip, session_user.psd_count - 1);
                    log_to_file(log_msg);

                    char ubus_query[1024];
                    snprintf(ubus_query, sizeof(ubus_query), "{\"ubus_rpc_session\":\"%s\"}", session_user.psds[i]->client_sid);
                    execute_ubus_command("session", "destroy", ubus_query);

                    free(session_user.psds[i]);
                    session_user.psds[i] = NULL;

                    for (int j = i; j < session_user.psd_count - 1; ++j) {
                        session_user.psds[j] = session_user.psds[j + 1];
                    }

                    session_user.psd_count--;
                    break;
                }
            }

            pthread_mutex_unlock(&lock);
            break;
        }

        default:
            break;
    }
    return 0;
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p':
                PORT = atoi(optarg);
                break;
            case 'l':
                LOG_FILE = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s [-p port] [-l log_file]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    struct lws_context_creation_info info;
    struct lws_protocols protocols[] = {
        { "jsonrpc", websocket_callback, sizeof(per_session_data_t), LWS_BUFFER_SIZE },
        { NULL, NULL, 0, 0 }
    };

    pthread_mutex_init(&lock, NULL);
    session_user.psd_count = 0;
    memset(session_user.psds, 0, sizeof(session_user.psds));

    memset(&info, 0, sizeof(info));
    info.port = PORT;
    info.protocols = protocols;

    info.max_http_header_data = LWS_BUFFER_SIZE;
    info.max_http_header_pool = MAX_WSI_COUNT;
    info.timeout_secs = 0;

    signal(SIGUSR1, on_sigusr1);

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        log_to_file("Failed to create lws context.");
        return 1;
    }

    char log_msg[128];
    snprintf(log_msg, sizeof(log_msg), "WebSocket server started on ws://localhost:%d", PORT);
    log_to_file(log_msg);

    load_system_bootid_once();

    while (1) {
        lws_service(context, 1000);

        if (g_broadcast_5005) {
            g_broadcast_5005 = 0;
            trigger_broadcast_5005();
        }
    }

    lws_context_destroy(context);
    pthread_mutex_destroy(&lock);
    return 0;
}
