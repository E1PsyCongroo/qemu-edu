#include "test.h"

#include <stdio.h>

void test_musl_iozone() {
    puts("#### OS COMP TEST GROUP START iozone-musl ####");
    puts("iozone automatic measurements");
    run_test((char *[]){"/musl/iozone", "-a", "-r", "1k", "-s", "4m", NULL});
    puts("#### OS COMP TEST GROUP END iozone-musl ####");
}
