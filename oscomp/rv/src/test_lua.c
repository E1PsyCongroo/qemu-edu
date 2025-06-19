#include "test.h"

#include <stdio.h>

static const char *tests[] = {
    "date.lua",
    "file_io.lua",
    "max_min.lua",
    "random.lua",
    "remove.lua",
    "round_num.lua",
    "sin30.lua",
    "sort.lua",
    "strings.lua"
};

void test_musl_lua() {
    puts("#### OS COMP TEST GROUP START libctest-lua ####");
    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int r = run_test((char *const[]){"/musl/lua", tests[i], NULL});
        if (r == 0) {
            printf("testcase lua %s success\n", tests[i]);
        } else {
            printf("testcase lua %s fail%d\n", tests[i], r);
        }
    }
    puts("#### OS COMP TEST GROUP END lua-musl ####");
}
