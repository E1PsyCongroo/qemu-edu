#include <unistd.h>

#include "test.h"

int main() {
    chdir("/musl");

    test_busybox();
    
    return 0;
}
