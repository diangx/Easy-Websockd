#include "ewsd_exec.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include "ewsd_common.h"
#include "ewsd_log.h"

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
