#include <sys/stat.h>
#include <unistd.h>

void test_start_musl() {
    // mkdir("/lib", 0777);
    // link("/musl/lib/libc.so", "/lib/ld-linux-riscv64-lp64d.so.1");
    // link("/musl/lib/libc.so", "/lib/ld-musl-riscv64-sf.so.1");
    chdir("/musl");
}
