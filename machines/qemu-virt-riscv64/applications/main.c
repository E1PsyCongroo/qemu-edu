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
#include "rtthread.h"
#include "msh.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int main(void)
{
    rt_kprintf("Hello RISC-V\n");
    if (dfs_mount("virtio-blk0", "/", "ext", 0, NULL) != 0) {
        rt_kprintf("Failed to mount filesystem, errno=%d\n", errno);
        return -1;
    }
    
    mkdir("/block", 0777);
    if (dfs_mount("virtio-blk1", "/block", "ext", 0, NULL) != 0) {
        rt_kprintf("Failed to mount filesystem\n");
        return -1;
    }
    
    mkdir("/lib", 0777);
    dfs_file_symlink("/musl/lib/libc.so", "/lib/ld-linux-riscv64-lp64d.so.1");
    dfs_file_symlink("/musl/lib/libc.so", "/lib/ld-musl-riscv64-sf.so.1");

    // mkdir("/bin", 0777);
    // dfs_file_symlink("/musl/busybox", "/bin/busybox");
    // dfs_file_symlink("/musl/busybox", "/bin/sh");

    char name[] = "/block/test-all";
    // msh_exec(name, strlen(name));

    return 0;
}