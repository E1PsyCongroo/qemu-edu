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

static int mount_procfs(void)
{
    int ret;

    mkdir("/proc", 0777);
    ret = dfs_mount("proc", "/proc", "procfs", 0, NULL);
    if (ret < 0)
    {        
        rt_kprintf("Failed to mount procfs, errno=%d\n", errno);
        return ret;
    }

    rt_kprintf("procfs mounted at /proc\n");

}

static void read_proc_interrupts(void)
{
    struct dfs_file file;
    char buffer[256];
    int fd = open("/proc/interrupts", O_RDONLY, 0);
    
    if (fd < 0)
    {
        rt_kprintf("Failed to open /proc/interrupts, errno=%d\n", errno);
        return;
    }

    while (read(fd, buffer, sizeof(buffer) - 1) > 0)
    {
        buffer[sizeof(buffer) - 1] = '\0'; // Null-terminate the string
        rt_kprintf("%s", buffer);
    }

    close(fd);
}

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

    mount_procfs();
    
    mkdir("/lib", 0777);
    dfs_file_symlink("/musl/lib/libc.so", "/lib/ld-linux-riscv64-lp64d.so.1");
    dfs_file_symlink("/musl/lib/libc.so", "/lib/ld-musl-riscv64-sf.so.1");

    mkdir("/bin", 0777);
    dfs_file_symlink("/musl/busybox", "/bin/busybox");
    dfs_file_symlink("/musl/busybox", "/bin/sh");

    char name[] = "/block/test-all";
    // msh_exec(name, strlen(name));

    read_proc_interrupts();
    rt_kprintf("\n");

    return 0;
}