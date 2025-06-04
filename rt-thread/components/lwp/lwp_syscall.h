/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2019-11-12     Jesven       the first version
 */

#ifndef __LWP_SYSCALL_H__
#define __LWP_SYSCALL_H__

#ifdef RT_USING_MUSLLIBC
#include "libc_musl.h"
#endif

#include "syscall_generic.h"
#define _GNU_SOURCE
#include "sys/utsname.h"
#include "lwp_pid.h"

#include <stdint.h>
#include <rtthread.h>
#include <dfs_file.h>
#include <unistd.h>
#include <stdio.h>      /* rename() */
#include <sys/stat.h>
#include <sys/statfs.h> /* statfs() */
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>

#include "lwp_ipc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t id_t; /* may contain pid, uid or gid */

/*
 * Process priority specifications to get/setpriority.
 */
#define PRIO_MIN (-20)
#define PRIO_MAX 20

#define PRIO_PROCESS 0 /* only support lwp process */
#define PRIO_PGRP    1
#define PRIO_USER    2

typedef unsigned long long rlim_t;

struct rlimit
{
    rlim_t rlim_cur;
    rlim_t rlim_max;
};

const char *lwp_get_syscall_name(rt_uint32_t number);
const void *lwp_get_sys_api(rt_uint32_t number);

/* process */
sysret_t sys_exit(int value);
sysret_t sys_exit_group(int status);
sysret_t sys_nanosleep(const struct timespec *rqtp, struct timespec *rmtp);
sysret_t sys_exec(char *filename, int argc, char **argv, char **envp);
sysret_t sys_execve(const char *path, char *const argv[], char *const envp[]);
sysret_t sys_kill(int pid, int sig);
sysret_t sys_getpid(void);
sysret_t sys_getppid(void);
sysret_t sys_getpriority(int which, id_t who);
sysret_t sys_setpriority(int which, id_t who, int prio);
sysret_t syscall_clone(unsigned long flags, void *user_stack, int *new_tid, void *tls, int *clear_tid);
sysret_t sys_wait4(pid_t pid, int *status, int options, struct rusage *ru);
sysret_t sys_gettid(void);

/* filesystem */
ssize_t  sys_read(int fd, void *buf, size_t nbyte);
ssize_t sys_readv(int fd, void *user_iovec, int iovcnt);
ssize_t  sys_write(int fd, const void *buf, size_t nbyte);
ssize_t  sys_writev(int fd, void *user_iovec, int iovcnt);
size_t   sys_lseek(int fd, size_t offset, int whence);
sysret_t sys_open(const char *name, int mode, ...);
sysret_t sys_openat(int dirfd, const char *name, int flag, mode_t mode);
sysret_t sys_close(int fd);
sysret_t sys_ioctl(int fd, unsigned long cmd, void *data);
sysret_t sys_fstat(int file, struct stat *buf);
sysret_t sys_poll(struct pollfd *fds, nfds_t nfds, int timeout);
sysret_t sys_fcntl(int fd, int cmd, int arg);
sysret_t sys_dup(int oldfd);
sysret_t sys_dup2(int oldfd, int new);
sysret_t sys_link(const char *existing, const char *new);
sysret_t sys_unlinkat(int dirfd, const char *pathname);
sysret_t sys_mount(char *source, char *target, char *filesystemtype, unsigned long mountflags, void *data);
sysret_t sys_umount2(char *__special_file, int __flags);
sysret_t sys_getcwd(char *buf, size_t size);
sysret_t sys_chdir(const char *path);
sysret_t sys_fchdir(int fd);
sysret_t sys_mkdir(int dirfd, const char *path, mode_t mode);
sysret_t sys_getdents(int fd, struct libc_dirent *dirp, size_t nbytes);
sysret_t sys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
sysret_t sys_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
size_t sys_lseek(int fd, size_t offset, int whence);

/* mm */
rt_base_t sys_brk(void *addr);
void     *sys_mmap2(void *addr, size_t length, int prot, int flags, int fd, size_t pgoffset);
sysret_t  sys_munmap(void *addr, size_t length);
sysret_t sys_mprotect(void *addr, size_t len, int prot);

/* other */
sysret_t sys_gettimeofday(struct timeval *tp, struct timezone *tzp);
sysret_t sys_settimeofday(const struct timeval *tv, const struct timezone *tzp);
sysret_t sys_get_uid();
sysret_t sys_get_euid();
sysret_t sys_uname(struct utsname *uts);
sysret_t sys_pipe(int fd[2]);
sysret_t sys_set_tid_address(int *tidptr);
sysret_t sys_times(void *tms);
sysret_t sys_getrlimit(unsigned int resource, unsigned long rlim[2]);
sysret_t sys_prlimit64(pid_t pid, unsigned int resource, const struct rlimit *new_rlim,struct rlimit *old_rlim);

/* snyc */
rt_sem_t   sys_sem_create(const char *name, rt_uint32_t value, rt_uint8_t flag);
sysret_t   sys_sem_delete(rt_sem_t sem);
sysret_t   sys_sem_take(rt_sem_t sem, rt_int32_t time);
sysret_t   sys_sem_release(rt_sem_t sem);
rt_mutex_t sys_mutex_create(const char *name, rt_uint8_t flag);
sysret_t   sys_mutex_delete(rt_mutex_t mutex);
sysret_t   sys_mutex_take(rt_mutex_t mutex, rt_int32_t time);
sysret_t   sys_mutex_release(rt_mutex_t mutex);

/* event */
rt_event_t sys_event_create(const char *name, rt_uint8_t flag);
sysret_t   sys_event_delete(rt_event_t event);
sysret_t   sys_event_send(rt_event_t event, rt_uint32_t set);
sysret_t   sys_event_recv(rt_event_t event, rt_uint32_t set, rt_uint8_t opt, rt_int32_t timeout, rt_uint32_t *recved);

/* mailbox */
rt_mailbox_t sys_mb_create(const char *name, rt_size_t size, rt_uint8_t flag);
sysret_t     sys_mb_delete(rt_mailbox_t mb);
sysret_t     sys_mb_send(rt_mailbox_t mb, rt_ubase_t value);
sysret_t     sys_mb_send_wait(rt_mailbox_t mb, rt_ubase_t value, rt_int32_t timeout);
sysret_t     sys_mb_recv(rt_mailbox_t mb, rt_ubase_t *value, rt_int32_t timeout);

/* message */
rt_mq_t      sys_mq_create(const char *name, rt_size_t msg_size, rt_size_t max_msgs, rt_uint8_t flag);
sysret_t     sys_mq_delete(rt_mq_t mq);
sysret_t     sys_mq_send(rt_mq_t mq, void *buffer, rt_size_t size);
sysret_t     sys_mq_urgent(rt_mq_t mq, void *buffer, rt_size_t size);
sysret_t     sys_mq_recv(rt_mq_t mq, void *buffer, rt_size_t size, rt_int32_t timeout);

rt_thread_t  sys_thread_create(void *arg[]);
sysret_t     sys_thread_delete(rt_thread_t thread);
sysret_t     sys_thread_startup(rt_thread_t thread);
rt_thread_t  sys_thread_self(void);

/* channel */
sysret_t     sys_channel_open(const char *name, int flags);
sysret_t     sys_channel_close(int fd);
sysret_t     sys_channel_send(int fd, rt_channel_msg_t data);
sysret_t     sys_channel_send_recv(int fd, rt_channel_msg_t data, rt_channel_msg_t data_ret);
sysret_t     sys_channel_reply(int fd, rt_channel_msg_t data);
sysret_t     sys_channel_recv(int fd, rt_channel_msg_t data);
void         sys_enter_critical(void);
void         sys_exit_critical(void);

/* sched */
sysret_t sys_sched_yield(void);

/* clock */
sysret_t sys_clock_gettime(clockid_t clk, struct timespec *ts);

/* signal */
struct k_sigaction;
sysret_t sys_sigprocmask(int how, const sigset_t *sigset, sigset_t *oset, size_t size);
sysret_t sys_sigaction(int sig, const struct k_sigaction *act, struct k_sigaction *oact, size_t sigsetsize);
sysret_t sys_sigpending(sigset_t *set, size_t sigsetsize);

sysret_t sys_log(const char *log, int size);

sysret_t sys_futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2, int val3);
sysret_t sys_cacheflush(void *addr, int len, int cache);

sysret_t sys_setsid(void);
sysret_t sys_getsid(pid_t pid);
sysret_t sys_setpgid(pid_t pid, pid_t pgid);
sysret_t sys_getpgid(pid_t pid);
sysret_t sys_setitimer(int which, const struct itimerspec *restrict new, struct itimerspec *restrict old);
sysret_t sys_sigtimedwait(const sigset_t *sigset, siginfo_t *info, const struct timespec *timeout, size_t sigsize);

sysret_t sys_tkill(int tid, int sig);

#ifdef __cplusplus
}
#endif

#endif
