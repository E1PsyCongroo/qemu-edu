#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>

#include "test.h"

int main() {
    chdir("/musl");
    char buffer[256];
    getcwd(buffer, sizeof(buffer));
    printf("getcwd=%s\n", buffer);
    
    test_start_musl();
    test_musl_lua();
    test_musl_basic();
    test_musl_busybox();
    test_musl_libc();
    
    return 0;
}
