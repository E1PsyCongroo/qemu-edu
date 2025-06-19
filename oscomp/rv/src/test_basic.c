#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include "test.h"

static const char *tests[] = {
    "brk",
    "chdir",
    "clone",
    "close",
    "dup2",
    "dup",
    "execve",
    "exit",
    "fork",
    "fstat",
    "getcwd",
    "getdents",
    "getpid",
    "getppid",
    "gettimeofday",
    "mkdir_",
    "mmap",
    "mount",
    "munmap",
    "openat",
    "open",
    "pipe",
    "read",
    "sleep",
    "times",
    "umount",
    "uname",
    "unlink",
    "wait",
    "waitpid",
    "write"
};

void test_musl_basic() {
    chdir("/musl/basic");
    puts("#### OS COMP TEST GROUP START basic-musl ####");
    char buffer[256];
    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        snprintf(buffer, sizeof(buffer), "/musl/basic/%s", tests[i]);
        run_test((char *const[]){buffer, NULL});
    }
    puts("#### OS COMP TEST GROUP END basic-musl ####");
    chdir("/musl");
}
