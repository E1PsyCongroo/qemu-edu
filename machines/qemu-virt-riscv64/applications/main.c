/*
 * Copyright (c) 2006-2018, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 */

#include "dfs_file.h"
#include "dfs_fs.h"
#include "klibc/kstring.h"
#include "sys/unistd.h"
#include <rtthread.h>
#include <rthw.h>
#include <sys/stat.h>

int main(void)
{
    rt_kprintf("Hello RISC-V\n");
    if (dfs_mount("virtio-blk0", "/", "ext", 0, NULL) != 0) {
        rt_kprintf("Failed to mount filesystem\n");
        return -1;
    }
    mkdir("/lib", 0777);
    dfs_file_symlink("/musl/lib/libc.so", "/lib/ld-linux-riscv64-lp64.so.1");
    dfs_file_symlink("/dev/tty", "/dev/ttyS0");

    int fildes[2];
    pipe(fildes);
    rt_kprintf("pipe fd: %d %d\n", fildes[0], fildes[1]);

    char buf[1024];
    rt_memset(buf, 'a', sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    int ret = write(fildes[1], buf, sizeof(buf));
    if (ret < 0) {
        rt_kprintf("write failed: %d\n", ret);
    } else {
        rt_kprintf("write %d bytes: %s\n", ret, buf);
    }
    
    ret = read(fildes[0], buf, sizeof(buf));
    if (ret < 0) {
        rt_kprintf("read failed: %d\n", ret);
    } else {
        rt_kprintf("read %d bytes: %s\n", ret, buf);
    }

    rt_kprintf("END of main\n");

    return 0;
}
