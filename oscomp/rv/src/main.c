#include <unistd.h>
#include <sys/stat.h>

#include "test.h"

int main() {
    chdir("/musl");
    
    test_start_musl();
    test_musl_lua();
    test_musl_busybox();
    test_musl_libc();
    test_musl_iozone();

    asm volatile (
        "li a7, 1024\n"
        "ecall"
    );
    
    return 0;
}
