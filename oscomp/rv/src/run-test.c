#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

int run_test(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        char *const envp[] = { NULL }; // No environment variables
        execve(argv[0], argv, envp);
        perror("execvp");
        exit(127);
    } else {
        int status, r;
        do {
            r = waitpid(pid, &status, 0);
        } while (r == -1 && errno == EINTR);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else {
            return -1;
        }
    }
}