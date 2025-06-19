#include <stdio.h>
#include <string.h>
#include "test.h"

static const char *tests[] = {
    "echo \"#### independent command test\"",
    "ash -c exit",
    "sh -c exit",
    "basename /aaa/bbb",
    "cal",
    "clear",
    "date",
    "df",
    "dirname /aaa/bbb",
    "dmesg",
    "du",
    "expr 1 + 1",
    "false",
    "true",
    "which ls",
    "uname",
    "uptime",
    "printf \"abc\\n\"",
    "ps",
    "pwd",
    "free",
    "hwclock",
    "kill 10",
    "ls",
    "sleep 1",
    "echo \"#### file opration test\"",
    // "touch test.txt",
    "echo \"hello world\" > test.txt",
    "cat test.txt",
    "cut -c 3 test.txt",
    "od test.txt",
    "head test.txt",
    "tail test.txt",
    "hexdump -C test.txt",
    "md5sum test.txt",
    "echo \"ccccccc\" >> test.txt",
    "echo \"bbbbbbb\" >> test.txt",
    "echo \"aaaaaaa\" >> test.txt",
    "echo \"2222222\" >> test.txt",
    "echo \"1111111\" >> test.txt",
    "echo \"bbbbbbb\" >> test.txt",
    "sort test.txt | ./busybox uniq",
    "stat test.txt",
    "strings test.txt",
    "wc test.txt",
    "[ -f test.txt ]",
    "more test.txt",
    "rm test.txt",
    "mkdir test_dir",
    "mv test_dir test",
    "rmdir test",
    "grep hello busybox_cmd.txt",
    "cp busybox_cmd.txt busybox_cmd.bak",
    "rm busybox_cmd.bak",
    "find -name \"busybox_cmd.txt\""
};

void test_musl_busybox() {
    puts("#### OS COMP TEST GROUP START busybox-musl ####");
    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        char command[256];
        snprintf(command, sizeof(command), "eval \"/musl/busybox %s\"", tests[i]);
        
        int result = run_test((char *const[]){"/musl/busybox", "sh", "-c", command, NULL});
        
        int success = strcmp(tests[i], "false") == 0 ? result != 0 : result == 0;
        if (success) {
            printf("testcase busybox %s success\n", tests[i]);
        } else {
            printf("testcase busybox %s fail\n", tests[i]);
        }
    }
    puts("#### OS COMP TEST GROUP END busybox-musl ####");
}
