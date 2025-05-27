/*
 * Copyright (c) 2006-2025 RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2018-06-10     Bernard      first version
 * 2021-02-03     lizhirui     add limit condition for network syscall and add 64-bit arch support
 * 2021-02-06     lizhirui     fix some bugs
 * 2021-02-12     lizhirui     add 64-bit support for sys_brk
 * 2021-02-20     lizhirui     fix some warnings
 * 2023-03-13     WangXiaoyao  Format & fix syscall return value
 * 2023-07-06     Shell        adapt the signal API, and clone, fork to new implementation of lwp signal
 * 2023-07-27     Shell        Move tid_put() from lwp_free() to sys_exit()
 * 2023-11-16     xqyjlj       fix some syscalls (about sched_*, get/setpriority)
 * 2023-11-17     xqyjlj       add process group and session support
 * 2023-11-30     Shell        Fix sys_setitimer() and exit(status)
 */
#include "lwp_syscall.h"
#include "rttypes.h"
#define __RT_IPC_SOURCE__
#define _GNU_SOURCE

/* RT-Thread System call */
#include <rtthread.h>
#include <rthw.h>
#include <board.h>

#define DBG_TAG    "lwp.syscall"
#define DBG_LVL    DBG_INFO
#include <rtdbg.h>

#include "syscall_generic.h"

// #include "libc_musl.h"
// #include "lwp_internal.h"

#include <mm_aspace.h>
#include <lwp_user_mm.h>
#include <lwp_arch.h>


#include <fcntl.h>
#include <sys/utsname.h>

#ifdef RT_USING_DFS
#include <eventfd.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <dfs_file.h>
#ifdef RT_USING_DFS_V2
#include <dfs_dentry.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <sys/statfs.h> /* statfs() */
#include <sys/timerfd.h>
#include <sys/ioctl.h>
#ifdef RT_USING_MUSLLIBC
#include <sys/signalfd.h>
#endif
#endif

#ifdef RT_USING_SAL
    #include <netdev_ipaddr.h>
    #include <netdev.h>

    #include <sal_netdb.h>
    #include <sal_socket.h>
    #include <sys/socket.h>

#endif /* RT_USING_SAL */

#if (defined(RT_USING_SAL) && defined(SAL_USING_POSIX))
    #include <sys/socket.h>

    #define SYSCALL_NET(f)      f
#else
    #define SYSCALL_NET(f)      SYSCALL_SIGN(sys_notimpl)
#endif /* (defined(RT_USING_SAL) && defined(SAL_USING_POSIX)) */

#if defined(RT_USING_DFS) && defined(ARCH_MM_MMU)
    #define SYSCALL_USPACE(f)   f
#else
    #define SYSCALL_USPACE(f)   SYSCALL_SIGN(sys_notimpl)
#endif /* defined(RT_USING_DFS) && defined(ARCH_MM_MMU) */

#include <sched.h>

#include <sys/sysinfo.h>

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK   0x0001
#endif /* GRND_NONBLOCK */

#ifndef RT_USING_POSIX_TIMER
#error "No definition RT_USING_POSIX_TIMER"
#endif /* RT_USING_POSIX_TIMER */

#ifndef RT_USING_POSIX_CLOCK
#error "No definition RT_USING_POSIX_CLOCK"
#endif /* RT_USING_POSIX_CLOCK */

sysret_t sys_notimpl(void)
{
    return -ENOSYS;
}

#ifndef LWP_USING_RUNTIME
sysret_t lwp_teardown(struct rt_lwp *lwp, void (*cb)(void))
{
    /* if no LWP_USING_RUNTIME configured */
    return -ENOSYS;
}
#endif

const static struct rt_syscall_def func_table[] = {
    [17]=SYSCALL_SIGN(sys_getcwd),
    [59]=SYSCALL_SIGN(sys_pipe),
    [23]=SYSCALL_SIGN(sys_dup),
    [24]=SYSCALL_SIGN(sys_dup2),
    [49]=SYSCALL_SIGN(sys_chdir),
    [56]=SYSCALL_SIGN(sys_openat),
    [57]=SYSCALL_SIGN(sys_close),
    [61]=SYSCALL_SIGN(sys_getdents),
    [63]=SYSCALL_SIGN(sys_read),
    [64]=SYSCALL_SIGN(sys_write),
    [37]=SYSCALL_SIGN(sys_link),
    [35]=SYSCALL_SIGN(sys_unlinkat),
    [34]=SYSCALL_SIGN(sys_mkdir),
    [39]=SYSCALL_SIGN(sys_umount2),
    [40]=SYSCALL_SIGN(sys_mount),
    [80]=SYSCALL_SIGN(sys_fstat),
    [220]=SYSCALL_SIGN(syscall_clone),
    [221]=SYSCALL_SIGN(sys_execve),
    [260]=SYSCALL_SIGN(sys_wait4),
    [93]=SYSCALL_SIGN(sys_exit),
    [173]=SYSCALL_SIGN(sys_getppid),
    [172]=SYSCALL_SIGN(sys_getpid),
    [214]=SYSCALL_SIGN(sys_brk),
    [215]=SYSCALL_SIGN(sys_munmap),
    [222]=SYSCALL_SIGN(sys_mmap2),
    [160]=SYSCALL_SIGN(sys_uname),
    [124]=SYSCALL_SIGN(sys_sched_yield),
    [169]=SYSCALL_SIGN(sys_gettimeofday),
    [101]=SYSCALL_SIGN(sys_nanosleep),
    [96]=SYSCALL_SIGN(sys_set_tid_address),
    [174]=SYSCALL_SIGN(sys_get_uid),
    [29]=SYSCALL_SIGN(sys_ioctl),
    [94]=SYSCALL_SIGN(sys_exit_group),
    [113]=SYSCALL_SIGN(sys_clock_gettime),
    [25]=SYSCALL_SIGN(sys_fcntl),
    [66]=SYSCALL_SIGN(sys_writev),
    [71]=SYSCALL_SIGN(sys_sendfile),
    [134]=SYSCALL_SIGN(sys_sigaction),
    [135]=SYSCALL_SIGN(sys_sigprocmask),
    [175]=SYSCALL_SIGN(sys_get_euid),
    [73]=SYSCALL_SIGN(sys_poll),
    [178]=SYSCALL_SIGN(sys_gettid),
    [153]=SYSCALL_SIGN(sys_times)
};

const void *lwp_get_sys_api(rt_uint32_t number)
{
    const void *func = (const void *)sys_notimpl;

    if (number == 0xff)
    {
        func = (void *)sys_log;
    }
    else
    {
        // number -= 1;
        if (number < sizeof(func_table) / sizeof(func_table[0]))
        {
            func = func_table[number].func;
            LOG_I("SYSCALL [%d]%s", number, func_table[number].name);
            // rt_kprintf("SYSCALL name=%s\n", func_table[number].name);
        }
        else
        {
            LOG_I("Unimplement syscall %d", number);
        }
    }

    if (func == RT_NULL) {
        func = (void *)sys_notimpl;
        LOG_I("SYSCALL id=%d not implement", number);
    }

    return func;
}

const char *lwp_get_syscall_name(rt_uint32_t number)
{
    const char *name = "sys_notimpl";

    if (number == 0xff)
    {
        name = "sys_log";
    }
    else
    {
        number -= 1;
        if (number < sizeof(func_table) / sizeof(func_table[0]))
        {
            name = (char*)func_table[number].name;
        }
        else
        {
                LOG_I("Unimplement syscall %d", number);
        }
    }

    /* skip sys_ */
    return name;
}
