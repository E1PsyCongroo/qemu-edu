#include "lwp.h"
#include "lwp_pid.h"
#include "lwp_user_mm.h"
#include "lwp_internal.h"

#include "rtdbg.h"
#include "rtthread.h"
#include "syscall_generic.h"

/**
 * @brief Terminates all threads in the current thread group.
 *
 * This system call ends execution for all threads within the same thread group,
 * releasing resources such as memory and file descriptors. It is typically used
 * in multithreaded environments to ensure a clean exit for the entire process.
 *
 * @param value The exit code to be returned to the parent process.
 * @return sysret_t: return value of the system call execution.
 */
sysret_t sys_exit_group(int value)
{
    sysret_t       rc = 0;
    lwp_status_t   lwp_status;
    struct rt_lwp *lwp = lwp_self();

    if (lwp)
    {
        lwp_status = LWP_CREATE_STAT_EXIT(value);
        lwp_exit(lwp, lwp_status);
    }
    else
    {
        LOG_E("Can't find matching process of current thread");
        rc = -EINVAL;
    }

    return rc;
}

/**
  * @brief Terminates the calling thread and exits the process.
  *
  * This system call ends the execution of the calling thread and the process
  * it belongs to.
  *
  * @param status The exit code to be returned to the parent process.
  *               A value of 0 typically indicates successful execution, while
  *               non-zero values indicate an error or specific exit condition.
  * @return sysret_t: return value of the system call execution.
  *
  * @note Unlike `sys_exit_group`, which terminates all threads in a thread group,
  *       `sys_exit` only terminates the calling thread and the process.
  */
sysret_t sys_exit(int status)
{
    sysret_t    rc = 0;
    rt_thread_t tid;

    tid = rt_thread_self();
    if (tid && tid->lwp)
    {
        lwp_thread_exit(tid, status);
    }
    else
    {
        LOG_E("Can't find matching process of current thread");
        rc = -EINVAL;
    }

    return rc;
}

/**
 * @brief Suspends execution for a specified amount of time.
 *
 * This system call suspends the execution of the calling thread for the duration
 * specified by the `rqtp` argument. The `rqtp` argument is a pointer to a `struct timespec`
 * that defines the sleep time in seconds and nanoseconds. If the sleep is interrupted by a signal,
 * the function may return early with the remaining time in `rmtp`, which is an optional argument.
 *
 * @param rqtp A pointer to a `struct timespec` that specifies the requested sleep time.
 *             The structure contains two fields: `tv_sec` (seconds) and `tv_nsec` (nanoseconds).
 * @param rmtp A pointer to a `struct timespec` where the remaining time will be stored if the
 *             sleep is interrupted by a signal. This can be `NULL` if the remaining time is not needed.
 * @return On success, returns `0`. On failure, returns `errno` to indicate the error.
 *
 * @note The `timespec` structure has two fields:
 *       - `tv_sec`: The number of whole seconds to sleep.
 *       - `tv_nsec`: The number of nanoseconds to sleep after the seconds. This value should be
 *         in the range [0, 1,000,000,000) nanoseconds.
 *
 * @warning Ensure that the values in `rqtp` are within valid ranges. A `tv_nsec` value greater than
 *          or equal to 1,000,000,000 will result in an error. If `rmtp` is provided, the caller
 *          must ensure the buffer is large enough to store the remaining time.
 *
 * @see sys_sleep(), clock_nanosleep(), nanosleep()
 */
sysret_t sys_nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
    int ret = 0;
    LOG_D("sys_nanosleep\n");
    if (!lwp_user_accessable((void *)rqtp, sizeof *rqtp))
        return -EFAULT;

    struct timespec rqtp_k;
    struct timespec rmtp_k;

    lwp_get_from_user(&rqtp_k, (void *)rqtp, sizeof rqtp_k);
    ret = nanosleep(&rqtp_k, &rmtp_k);
    if ((ret != -1 || rt_get_errno() == EINTR) && rmtp && lwp_user_accessable((void *)rmtp, sizeof *rmtp))
    {
        lwp_put_to_user(rmtp, (void *)&rmtp_k, sizeof rmtp_k);
        if (ret != 0)
            return -EINTR;
    }
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Replaces the current process with a new process.
 *
 * This system call loads a new program into the current process's address space,
 * replacing the current program with the one specified by `filename`. It passes the
 * arguments `argv` and environment variables `envp` to the new program. If the execution
 * is successful, the current process is completely replaced, and no code after the
 * `sys_exec` call is executed. If an error occurs, the system call returns, and the
 * current process continues executing.
 *
 * @param filename The path to the executable file to be run. This can be an absolute
 *                 or relative path.
 * @param argc The number of arguments passed to the new program. This includes the
 *             executable name itself as the first argument.
 * @param argv An array of strings (character pointers), where each string is an argument
 *             passed to the new program. The first element (`argv[0]`) is conventionally
 *             the name of the executable.
 * @param envp An array of strings representing the environment variables for the new
 *             process. The array is terminated by a `NULL` pointer.
 * @return This function does not return on success, as the current process is replaced.
 *         On failure, it returns error code to indicate the error.
 *
 * @note The new process inherits most of the attributes of the current process, such
 *       as file descriptors, unless explicitly modified. It is important that `argv`
 *       and `envp` are properly formatted, and the `filename` points to a valid executable.
 *
 * @warning If `filename` is invalid or not an executable, or if the arguments or
 *          environment variables are incorrectly set, the system call will fail and
 *          return `-1`. Ensure that the executable file is accessible and that `argv`
 *          and `envp` are properly constructed.
 *
 * @see execve(), execvp(), execv(), execle()
 */
sysret_t sys_exec(char *filename, int argc, char **argv, char **envp)
{
    int   ret       = 0;
    int   len       = 0;
    char *kfilename = RT_NULL;

    len = lwp_user_strlen(filename);
    if (len <= 0)
    {
        return -EFAULT;
    }

    //  kfilename = (char *)kmem_get(len + 1);
    kfilename = (char *)rt_malloc(len + 1);
    if (!kfilename)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kfilename, (void *)filename, len + 1) != (len + 1))
    {
        //  kmem_put(kfilename);
        rt_free(kfilename);
        return -EFAULT;
    }

    ret = lwp_execve(kfilename, 0, argc, argv, envp);

    //  kmem_put(kfilename);
    rt_free(kfilename);

    return ret;
}

/**
 * @brief Sends a signal to a process or a group of processes.
 *
 * This system call sends the signal specified by `signo` to the process or process group
 * identified by `pid`. If `pid` is positive, the signal is sent to the process with the
 * specified process ID. If `pid` is `0`, the signal is sent to all processes in the
 * same process group as the caller. If `pid` is `-1`, the signal is sent to all processes
 * except for the caller. If `pid` is less than `-1`, the signal is sent to all processes
 * in the process group with the process group ID equal to `-pid`.
 *
 * @param pid The process ID or process group ID to which the signal is to be sent.
 *            - A positive value sends the signal to the process with that ID.
 *            - `0` sends the signal to all processes in the same process group as the caller.
 *            - `-1` sends the signal to all processes except the caller.
 *            - A negative value sends the signal to all processes in the process group
 *              with the process group ID equal to `-pid`.
 * @param signo The signal to send. This is an integer value that specifies the signal
 *              type. Common signal values include:
 *              - `SIGTERM` (terminate process)
 *              - `SIGKILL` (force kill process)
 *              - `SIGSTOP` (suspend process)
 *              - `SIGCONT` (resume process)
 * @return On success, returns `0`. On failure, it returns error code to indicate the error.
 *
 * @note Signals are a mechanism for inter-process communication, allowing processes
 *       to send notifications or requests to other processes. The behavior of signals
 *       depends on the signal type and how the receiving process handles them.
 *
 * @warning The `signo` value must be a valid signal number. Passing an invalid signal
 *          number or an invalid `pid` may result in an error. Additionally, some signals
 *          (e.g., `SIGKILL`) cannot be caught or ignored by processes.
 *
 * @see signal(), killpg(), raise()
 */
sysret_t sys_kill(int pid, int signo)
{
    rt_err_t       kret = 0;
    sysret_t       sysret;
    struct rt_lwp *lwp = RT_NULL;

    /* handling the semantics of sys_kill */
    if (pid > 0)
    {
        /**
          * Brief: Match the pid and send signal to the lwp if found
          * Note: Critical Section
          * - pid tree (READ. since the lwp is fetch from the pid tree, it must stay there)
          */
        lwp_pid_lock_take();
        lwp = lwp_from_pid_raw_locked(pid);
        if (lwp)
        {
            lwp_ref_inc(lwp);
            lwp_pid_lock_release();
        }
        else
        {
            lwp_pid_lock_release();
            kret = -RT_ENOENT;
        }

        if (lwp)
        {
            kret = lwp_signal_kill(lwp, signo, SI_USER, 0);
            lwp_ref_dec(lwp);
        }
    }
    else if (pid < -1 || pid == 0)
    {
        pid_t             pgid = 0;
        rt_processgroup_t group;

        if (pid == 0)
        {
            /**
              * sig shall be sent to all processes (excluding an unspecified set
              * of system processes) whose process group ID is equal to the process
              * group ID of the sender, and for which the process has permission to
              * send a signal.
              */
            pgid = lwp_pgid_get_byprocess(lwp_self());
        }
        else
        {
            /**
              * sig shall be sent to all processes (excluding an unspecified set
              * of system processes) whose process group ID is equal to the absolute
              * value of pid, and for which the process has permission to send a signal.
              */
            pgid = -pid;
        }

        group = lwp_pgrp_find(pgid);
        if (group != RT_NULL)
        {
            PGRP_LOCK(group);
            kret = lwp_pgrp_signal_kill(group, signo, SI_USER, 0);
            PGRP_UNLOCK(group);
        }
        else
        {
            kret = -ECHILD;
        }
    }
    else if (pid == -1)
    {
        /**
          * sig shall be sent to all processes (excluding an unspecified set
          * of system processes) for which the process has permission to send
          * that signal.
          */
        kret = lwp_signal_kill_all(signo, SI_USER, 0);
    }

    switch (kret)
    {
    case -RT_ENOENT:
    case -ECHILD:
        sysret = -ESRCH;
        break;
    case -RT_EINVAL:
        sysret = -EINVAL;
        break;
    case -RT_ENOSYS:
        sysret = -ENOSYS;
        break;

    /**
          * kill() never returns ENOMEM, so return normally to caller.
          * IEEE Std 1003.1-2017 says the kill() function is successful
          * if the process has permission to send sig to any of the
          * processes specified by pid.
          */
    case -RT_ENOMEM:
    default:
        sysret = 0;
    }
    return sysret;
}

/**
 * @brief Retrieves the process ID of the calling process.
 *
 * This system call returns the process ID (PID) of the calling process. The PID is a
 * unique identifier assigned by the operating system to each running process. It can
 * be used to refer to or manipulate the process in subsequent system calls.
 *
 * @return The PID of the calling process. On failure, returns `-1` and sets `errno`
 *         to indicate the error (although this function typically does not fail).
 *
 * @note The PID returned by this function is a positive integer, and it remains
 *       unique during the lifetime of the process. This value can be used to manage
 *       the process, including sending signals or querying process information.
 *
 * @warning This function does not take any arguments and is typically used when
 *          a process needs to obtain its own PID for management or logging purposes.
 *
 * @see getppid(), getuid(), getgid()
 */
sysret_t sys_getpid(void)
{
    return lwp_getpid();
}

/**
 * @brief Retrieves the parent process ID of the calling process.
 *
 * This system call returns the process ID (PID) of the parent process of the calling process.
 * The parent process is the process that created the calling process, typically through a
 * system call like `fork()`. This information can be useful for process management and
 * for determining the hierarchy of processes.
 *
 * @return The PID of the parent process. If the calling process has no parent (for example,
 *         the init process), it typically returns `1` as the PID of the system's "root" process.
 *         On failure, returns `-1` and sets `errno` to indicate the error (although this function
 *         typically does not fail).
 *
 * @note The `getppid()` function is commonly used when a process needs to know which
 *       process is responsible for it, or for managing relationships between parent and child processes.
 *
 * @warning This function does not take any arguments and is typically used when the
 *          process requires information about its parent. It should not be confused with `getpid()`,
 *          which retrieves the PID of the calling process itself.
 *
 * @see getpid(), getuid(), getgid()
 */
sysret_t sys_getppid(void)
{
    rt_lwp_t process;

    process = lwp_self();
    if (process->parent == RT_NULL)
    {
        LOG_E("%s: process %d has no parent process", __func__, lwp_to_pid(process));
        return 0;
    }
    else
    {
        return lwp_to_pid(process->parent);
    }
}

static void lwp_struct_copy(struct rt_lwp *dst, struct rt_lwp *src)
{
    dst->end_heap   = src->end_heap;
    dst->brk        = src->brk;
    dst->lwp_type   = src->lwp_type;
    dst->text_entry = src->text_entry;
    dst->text_size  = src->text_size;
    dst->data_entry = src->data_entry;
    dst->data_size  = src->data_size;
    dst->args       = src->args;
    dst->background = src->background;
    dst->tty        = src->tty;

    /* terminal API */
    dst->term_ctrlterm = src->term_ctrlterm;

    rt_memcpy(dst->cmd, src->cmd, RT_NAME_MAX);
    if (src->exe_file)
    {
        if (dst->exe_file)
        {
            rt_free(dst->exe_file);
        }
        dst->exe_file = strndup(src->exe_file, DFS_PATH_MAX);
    }

    rt_memcpy(&dst->signal.sig_action, &src->signal.sig_action, sizeof(dst->signal.sig_action));
    rt_memcpy(&dst->signal.sig_action_mask, &src->signal.sig_action_mask, sizeof(dst->signal.sig_action_mask));
    rt_memcpy(&dst->signal.sig_action_nodefer, &src->signal.sig_action_nodefer, sizeof(dst->signal.sig_action_nodefer));
    rt_memcpy(&dst->signal.sig_action_onstack, &src->signal.sig_action_onstack, sizeof(dst->signal.sig_action_onstack));
    rt_memcpy(&dst->signal.sig_action_restart, &dst->signal.sig_action_restart, sizeof(dst->signal.sig_action_restart));
    rt_memcpy(&dst->signal.sig_action_siginfo, &dst->signal.sig_action_siginfo, sizeof(dst->signal.sig_action_siginfo));
    rt_memcpy(&dst->signal.sig_action_nocldstop, &dst->signal.sig_action_nocldstop, sizeof(dst->signal.sig_action_nocldstop));
    rt_memcpy(&dst->signal.sig_action_nocldwait, &dst->signal.sig_action_nocldwait, sizeof(dst->signal.sig_action_nocldwait));
    rt_strcpy(dst->working_directory, src->working_directory);
}

static int lwp_copy_files(struct rt_lwp *dst, struct rt_lwp *src)
{
    struct dfs_fdtable *dst_fdt;
    struct dfs_fdtable *src_fdt;

    src_fdt = &src->fdt;
    dst_fdt = &dst->fdt;
    /* init fds */
    dst_fdt->fds = rt_calloc(src_fdt->maxfd, sizeof(void *));
    if (dst_fdt->fds)
    {
        struct dfs_file *d_s;
        int              i;

        dst_fdt->maxfd = src_fdt->maxfd;

        dfs_file_lock();
        /* dup files */
        for (i = 0; i < src_fdt->maxfd; i++)
        {
            d_s = fdt_get_file(src_fdt, i);
            if (d_s)
            {
                dst_fdt->fds[i] = d_s;
                d_s->ref_count++;
            }
        }
        dfs_file_unlock();
        return 0;
    }
    return -RT_ERROR;
}

void lwp_cleanup(struct rt_thread *tid);
long _sys_clone_args(unsigned long flags, void *user_stack, int *new_tid, void *tls, int *clear_tid)
{
    // rt_kprintf("sys_clone_args: %lx %p %p %p %p\n", flags, user_stack, new_tid, tls, clear_tid);
    struct rt_lwp *lwp      = 0;
    rt_thread_t    thread   = RT_NULL;
    rt_thread_t    self     = rt_thread_self();
    struct rt_lwp *self_lwp = self->lwp;
    int            tid      = 0;
    rt_err_t       err;

    /*
       musl call flags (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
       | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS
       | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED);
       */

    /* check args */
    // if ((flags & (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SYSVSEM))
    //         != (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SYSVSEM))
    // {
    //     return -EINVAL;
    // }

    if ((flags & CLONE_PARENT_SETTID) == CLONE_PARENT_SETTID)
    {
        if (!lwp_user_accessable(new_tid, sizeof(int)))
        {
            return -EFAULT;
        }
    }

    if ((flags & CLONE_THREAD) == CLONE_THREAD)
    {
        lwp = self_lwp;
        lwp_ref_inc(lwp);

        if (!user_stack)
        {
            SET_ERRNO(EINVAL);
            goto fail;
        }

        if ((tid = lwp_tid_get()) == 0)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        thread = rt_thread_create(self->parent.name,
                                  RT_NULL,
                                  RT_NULL,
                                  self->stack_size,
                                  RT_SCHED_PRIV(self).init_priority,
                                  RT_SCHED_PRIV(self).init_tick);
        if (!thread)
        {
            goto fail;
        }

        thread->cleanup         = lwp_cleanup;
        thread->user_entry      = RT_NULL;
        thread->user_stack      = RT_NULL;
        thread->user_stack_size = 0;
    }
    else
    {
        lwp = lwp_create(LWP_CREATE_FLAG_ALLOC_PID);
        if (!lwp)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        if ((tid = lwp_tid_get()) == 0)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        if (lwp_user_space_init(lwp, 1) != 0)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        struct rt_lwp *self_lwp = self->lwp;

        if (lwp_fork_aspace(lwp, self_lwp) != 0)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        // lwp_struct_copy(lwp, self_lwp);

        /* copy lwp struct data */
        lwp_struct_copy(lwp, self_lwp);

        /* copy files */
        if (lwp_copy_files(lwp, self_lwp) != 0)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        /* create thread */

        thread = rt_thread_create(self->parent.name,
                                  RT_NULL,
                                  RT_NULL,
                                  self->stack_size,
                                  RT_SCHED_PRIV(self).init_priority,
                                  RT_SCHED_PRIV(self).init_tick);
        if (!thread)
        {
            SET_ERRNO(ENOMEM);
            goto fail;
        }

        thread->cleanup            = self->cleanup;
        thread->user_entry         = self->user_entry;
        thread->user_stack         = self->user_stack;
        thread->user_stack_size    = self->user_stack_size;
        thread->signal.sigset_mask = self->signal.sigset_mask;
        thread->thread_idr         = self->thread_idr;
        thread->clear_child_tid    = self->clear_child_tid;

        lwp_children_register(self_lwp, lwp);
    }

#ifdef RT_USING_SMP
    RT_SCHED_CTX(self).bind_cpu = lwp->bind_cpu;
#endif
    // thread->cleanup = lwp_cleanup;
    // thread->user_entry = RT_NULL;
    // thread->user_stack = RT_NULL;
    // thread->user_stack_size = 0;
    // thread->lwp = (void *)lwp;
    thread->tid = tid;
    thread->lwp = (void *)lwp;

    if ((flags & CLONE_SETTLS) == CLONE_SETTLS)
    {
        thread->thread_idr = tls;
    }
    if ((flags & CLONE_PARENT_SETTID) == CLONE_PARENT_SETTID)
    {
        *new_tid = (int)(tid);
    }
    if ((flags & CLONE_CHILD_CLEARTID) == CLONE_CHILD_CLEARTID)
    {
        thread->clear_child_tid = clear_tid;
    }

    if (lwp->debug)
    {
        rt_thread_control(thread, RT_THREAD_CTRL_BIND_CPU, (void *)0);
    }

    LWP_LOCK(lwp);
    rt_list_insert_after(&lwp->t_grp, &thread->sibling);
    LWP_UNLOCK(lwp);

    if ((flags & CLONE_THREAD) == CLONE_THREAD)
    {
        rt_thread_t self = rt_thread_self();
        /* copy origin stack */
        lwp_memcpy(thread->stack_addr, self->stack_addr, thread->stack_size);
        lwp_tid_set_thread(tid, thread);
        arch_set_thread_context(arch_clone_exit,
                                (void *)((char *)thread->stack_addr + thread->stack_size),
                                user_stack, &thread->sp);

        /* new thread never reach there */
        rt_thread_startup(thread);

        return (long)tid;
    }
    else
    {
        /* set pgid and sid */
        rt_processgroup_t group = lwp_pgrp_find(lwp_pgid_get_byprocess(self_lwp));
        if (group)
        {
            lwp_pgrp_insert(group, lwp);
        }
        else
        {
            LOG_W("the process group of pid: %d cannot be found", lwp_pgid_get_byprocess(self_lwp));
        }

        /* copy kernel stack context from self thread */
        lwp_memcpy(thread->stack_addr, self->stack_addr, self->stack_size);
        lwp_tid_set_thread(tid, thread);

        /* duplicate user objects */
        lwp_user_object_dup(lwp, self_lwp);

        if (user_stack == RT_NULL)
        {
            user_stack = arch_get_user_sp();
        }

        arch_set_thread_context(arch_fork_exit,
                                (void *)((char *)thread->stack_addr + thread->stack_size),
                                user_stack, &thread->sp);

        rt_thread_startup(thread);
        rt_kprintf("new thread pid: %d\n", lwp_to_pid(lwp));
        return lwp_to_pid(lwp);
    }

fail:
    err = GET_ERRNO();
    RT_ASSERT(err < 0);

    lwp_tid_put(tid);
    if (thread)
    {
        rt_thread_delete(thread);
    }
    if (lwp)
    {
        lwp_ref_dec(lwp);
    }
    return (long)err;
}

long _sys_clone(void *arg[])
{
    /*
       musl call flags (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND
       | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS
       | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED);
       */

    /* check args */
    if (!lwp_user_accessable(arg, sizeof(void *[SYS_CLONE_ARGS_NR])))
    {
        return -EFAULT;
    }

    unsigned long flags      = (unsigned long)(size_t)arg[0];
    void         *user_stack = arg[1];
    int          *new_tid    = (int *)arg[2];
    void         *tls        = (void *)arg[3];
    int          *clear_tid  = (int *)arg[4];

    return _sys_clone_args(flags, user_stack, new_tid, tls, clear_tid);
}

/**
 * @brief Creates a new process or thread (clone).
 *
 * This system call creates a new process or thread by duplicating the calling process.
 * The new process/thread begins execution by calling the function specified in the
 * `arg[]` array, which typically contains the necessary arguments or function pointer.
 * It is used to implement process/thread creation in the system and is often a lower-level
 * operation in process management.
 *
 * @param[in] arg   An array of arguments passed to the new process or thread. This could
 *                  include function pointers, structures, or any necessary data the
 *                  new process/thread will need to execute its work.
 *
 * @return long     Returns a status code or the process/thread ID of the newly created
 *                  process/thread. On success, it may return a positive value (such as a
 *                  thread ID). On failure, a negative value indicating the error is returned.
 *
 * @warning Be cautious when using this function as improper management of process/thread
 *          creation can lead to resource exhaustion, deadlocks, or other synchronization issues.
 */
sysret_t syscall_clone(unsigned long flags, void *user_stack, int *new_tid, void *tls, int *clear_tid)
{
    return _sys_clone_args(flags, user_stack, new_tid, tls, clear_tid);
}

#if 0
sysret_t _sys_fork(void) {
    int tid = 0;
    sysret_t falival = 0;
    struct rt_lwp *lwp = RT_NULL;
    struct rt_lwp *self_lwp = RT_NULL;
    rt_thread_t thread = RT_NULL;
    rt_thread_t self_thread = RT_NULL;
    void *user_stack = RT_NULL;
    rt_processgroup_t group;

    /* new lwp */
    lwp = lwp_create(LWP_CREATE_FLAG_ALLOC_PID);
    if (!lwp)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    /* new tid */
    if ((tid = lwp_tid_get()) == 0)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    /* user space init */
    if (lwp_user_space_init(lwp, 1) != 0)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    self_lwp = lwp_self();

    /* copy address space of process from this proc to forked one */
    if (lwp_fork_aspace(lwp, self_lwp) != 0)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    /* copy lwp struct data */
    lwp_struct_copy(lwp, self_lwp);

    /* copy files */
    if (lwp_copy_files(lwp, self_lwp) != 0)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    /* create thread */
    self_thread = rt_thread_self();

    thread = rt_thread_create(self_thread->parent.name,
            RT_NULL,
            RT_NULL,
            self_thread->stack_size,
            RT_SCHED_PRIV(self_thread).init_priority,
            RT_SCHED_PRIV(self_thread).init_tick);
    if (!thread)
    {
        SET_ERRNO(ENOMEM);
        goto fail;
    }

    thread->cleanup = self_thread->cleanup;
    thread->user_entry = self_thread->user_entry;
    thread->user_stack = self_thread->user_stack;
    thread->user_stack_size = self_thread->user_stack_size;
    thread->signal.sigset_mask = self_thread->signal.sigset_mask;
    thread->thread_idr = self_thread->thread_idr;
    thread->clear_child_tid = self_thread->clear_child_tid;
    thread->lwp = (void *)lwp;
    thread->tid = tid;

    LWP_LOCK(self_lwp);
    /* add thread to lwp process */
    rt_list_insert_after(&lwp->t_grp, &thread->sibling);
    LWP_UNLOCK(self_lwp);

    lwp_children_register(self_lwp, lwp);

    /* set pgid and sid */
    group = lwp_pgrp_find(lwp_pgid_get_byprocess(self_lwp));
    if (group)
    {
        lwp_pgrp_insert(group, lwp);
    }
    else
    {
        LOG_W("the process group of pid: %d cannot be found", lwp_pgid_get_byprocess(self_lwp));
    }

    /* copy kernel stack context from self thread */
    lwp_memcpy(thread->stack_addr, self_thread->stack_addr, self_thread->stack_size);
    lwp_tid_set_thread(tid, thread);

    /* duplicate user objects */
    lwp_user_object_dup(lwp, self_lwp);

    user_stack = arch_get_user_sp();
    arch_set_thread_context(arch_fork_exit,
            (void *)((char *)thread->stack_addr + thread->stack_size),
            user_stack, &thread->sp);

    rt_thread_startup(thread);
    return lwp_to_pid(lwp);
fail:
    falival = GET_ERRNO();

    if (tid != 0)
    {
        lwp_tid_put(tid);
    }
    if (thread)
    {
        rt_thread_delete(thread);
    }
    if (lwp)
    {
        lwp_ref_dec(lwp);
    }
    return falival;
}
#endif

/* arm needs to wrap fork/clone call to preserved lr & caller saved regs */

/**
 * @brief Creates a child process by duplicating the calling process.
 *
 * This system call creates a new child process by duplicating the calling process. The
 * new child process is a copy of the parent process, except for the returned value.
 * The child process starts executing from the point of the fork, but the return value
 * differs between the parent and child: the parent receives the process ID (PID) of the
 * child, and the child receives a return value of 0.
 *
 * @return sysret_t    Returns a status code indicating the result of the operation:
 *                      - A positive value (the child's PID) is returned to the parent.
 *                      - A value of 0 is returned to the child process.
 *                      - A negative value indicates an error (e.g., resource limits exceeded).
 *
 * @note This function is commonly used in operating systems to create new processes.
 *
 * @warning Be aware that improper management of child processes (such as failing to handle
 *          process termination or excessive forking) can lead to resource exhaustion or
 *          other system issues. Ensure proper process handling in the parent and child
 *          processes to avoid leaks and inconsistencies.
 */
// rt_weak sysret_t sys_fork(void)
// {
//     return _sys_fork();
// }

// rt_weak sysret_t sys_vfork(void)
// {
//     return sys_fork();
// }

#define _swap_lwp_data(lwp_used, lwp_new, type, member) \
    do {                                                \
        type tmp;                                       \
        tmp              = lwp_used->member;            \
        lwp_used->member = lwp_new->member;             \
        lwp_new->member  = tmp;                         \
    } while (0)

/**
 * @brief Executes a program in the current process.
 *
 * This system call replaces the current process image with a new program specified by the
 * `path` argument. It loads the program located at the given `path` and passes the arguments
 * (`argv`) and environment variables (`envp`) to it. This effectively replaces the calling
 * process with a new one, and if successful, it never returns. If there is an error, the current
 * process continues to execute, and an error code is returned.
 *
 * @param[in]  path   The path to the executable file to be executed. This should be an
 *                    absolute or relative file path to the program.
 * @param[in]  argv   An array of arguments to pass to the new program. The first element
 *                    (`argv[0]`) should typically be the name of the program, and the array
 *                    should be terminated with a `NULL` pointer.
 * @param[in]  envp   An array of environment variables to pass to the new program. This is
 *                    typically in the form of `key=value` strings, with the array terminated
 *                    by a `NULL` pointer.
 *
 * @return sysret_t  Returns a status code:
 *                    - `0`: The program was successfully executed (this value is
 *                      never returned since the process is replaced).
 *                   - Other error codes may indicate issues with the program execution
 *
 * @note If `execve` is successful, it does not return to the calling function. The process
 *       image is replaced by the new program.
 */
sysret_t sys_execve(const char *path, char * const argv[], char * const envp[])
{
    rt_err_t             error = -1;
    size_t               len;
    struct rt_lwp       *new_lwp = NULL;
    struct rt_lwp       *lwp;
    int                  uni_thread;
    rt_thread_t          thread;
    struct process_aux  *aux;
    struct lwp_args_info args_info;
    char                *kpath = RT_NULL;

    lwp        = lwp_self();
    thread     = rt_thread_self();
    uni_thread = 1;

    LWP_LOCK(lwp);
    if (lwp->t_grp.prev != &thread->sibling)
    {
        uni_thread = 0;
    }
    if (lwp->t_grp.next != &thread->sibling)
    {
        uni_thread = 0;
    }
    LWP_UNLOCK(lwp);

    if (!uni_thread)
    {
        return -EINVAL;
    }

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    kpath = rt_malloc(len + 1);
    if (!kpath)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kpath, (void *)path, len) != len)
    {
        rt_free(kpath);
        return -EFAULT;
    }
    kpath[len] = '\0';

    if (access(kpath, X_OK) != 0)
    {
        error = rt_get_errno();
        rt_free(kpath);
        return (sysret_t)error;
    }

    /* setup args */
    error = lwp_args_init(&args_info);
    if (error)
    {
        rt_free(kpath);
        return -ENOMEM;
    }

    if (argv)
    {
        error = lwp_args_put_argv(&args_info, (void *)argv);
        if (error)
        {
            error = -EFAULT;
            goto quit;
        }
    }

    if (envp)
    {
        error = lwp_args_put_envp(&args_info, (void *)envp);
        if (error)
        {
            error = -EFAULT;
            goto quit;
        }
    }

    /* alloc new lwp to operation */
    new_lwp = lwp_create(LWP_CREATE_FLAG_NONE);
    if (!new_lwp)
    {
        error = -ENOMEM;
        goto quit;
    }

    error = lwp_user_space_init(new_lwp, 0);
    if (error != 0)
    {
        error = -ENOMEM;
        goto quit;
    }

    /* file is a script ? */
    path = kpath;
    while (1)
    {
        error = lwp_args_load_script(&args_info, path);
        if (error != 0)
        {
            break;
        }
        path = lwp_args_get_argv_0(&args_info);
    }

    /* now load elf */
    if ((aux = lwp_argscopy(new_lwp, &args_info)) == NULL)
    {
        error = -ENOMEM;
        goto quit;
    }
    error = lwp_load(path, new_lwp, RT_NULL, 0, aux);
    if (error == RT_EOK)
    {
        int off            = 0;
        int last_backslash = 0;

        /* clear all user objects */
        lwp_user_object_clear(lwp);

        /* find last \ or / to get base name */
        while (1)
        {
            char c = path[off++];

            if (c == '\0')
            {
                break;
            }
            if (c == '\\' || c == '/')
            {
                last_backslash = off;
            }
        }

        /**
         * Set thread name and swap the data of lwp and new_lwp.
         * Since no other threads can access the lwp field, it't uneccessary to
         * take a lock here
         */
        RT_ASSERT(rt_list_entry(lwp->t_grp.prev, struct rt_thread, sibling) == thread);

        strncpy(thread->parent.name, path + last_backslash, RT_NAME_MAX - 1);
        strncpy(lwp->cmd, new_lwp->cmd, RT_NAME_MAX);
        rt_free(lwp->exe_file);
        lwp->exe_file = strndup(new_lwp->exe_file, DFS_PATH_MAX);

#ifdef ARCH_MM_MMU
        _swap_lwp_data(lwp, new_lwp, struct rt_aspace *, aspace);

        _swap_lwp_data(lwp, new_lwp, size_t, end_heap);
        _swap_lwp_data(lwp, new_lwp, size_t, brk);
#endif
        _swap_lwp_data(lwp, new_lwp, uint8_t, lwp_type);
        _swap_lwp_data(lwp, new_lwp, void *, text_entry);
        _swap_lwp_data(lwp, new_lwp, uint32_t, text_size);
        _swap_lwp_data(lwp, new_lwp, void *, data_entry);
        _swap_lwp_data(lwp, new_lwp, uint32_t, data_size);

        _swap_lwp_data(lwp, new_lwp, void *, args);

        lwp_thread_signal_detach(&thread->signal);
        rt_memset(&thread->signal.sigset_mask, 0, sizeof(thread->signal.sigset_mask));

        lwp_signal_detach(&lwp->signal);
        lwp_signal_init(&lwp->signal);

        /* to do: clsoe files with flag CLOEXEC, recy sub-thread */

        lwp_aspace_switch(thread);

        lwp_ref_dec(new_lwp);
        arch_start_umode(lwp->args,
                         lwp->text_entry,
                         (void *)USER_STACK_VEND,
                         (char *)thread->stack_addr + thread->stack_size);
        /* never reach here */
    }
    error = -EINVAL;
quit:
    if (kpath)
    {
        rt_free(kpath);
    }
    lwp_args_detach(&args_info);
    if (new_lwp)
    {
        lwp_ref_dec(new_lwp);
    }
    return error;
}

/**
 * @brief Waits for the termination of a child process.
 *
 * This function makes the calling process wait until one of its child processes terminates or until a
 * specified condition is met. The function retrieves information about the terminated child process,
 * including its exit status, and can also handle other process-related events, such as stopping or
 * continuing execution.
 *
 * @param[in] pid     The process ID of the child process to wait for. If `pid` is:
 *                    - `-1`: Wait for any child process.
 *                    - `0`: Wait for any child process in the same process group.
 *                    - > 0: Wait for the child process with the specified process ID.
 * @param[out] status A pointer to an integer where the exit status of the terminated child process will be stored.
 *                    This value provides information about the child's termination status, such as normal exit,
 *                    signal termination, etc.
 * @param[in] options A bitmask of options that control the behavior of the function. It can include:
 *                    - `WNOHANG`: Return immediately if no child has exited.
 *                    - `WUNTRACED`: Report status of stopped child processes.
 *                    - Other flags can be defined depending on the implementation.
 *
 * @return sysret_t  Returns the process ID of the child process that terminated on success, or a negative error code on failure.
 *
 * @note The `status` argument provides detailed information about the termination of the child process. To interpret this
 *       status, macros such as `WIFEXITED()`, `WIFSIGNALED()`, and `WEXITSTATUS()` are commonly used.
 *
 * @warning This function should be used carefully when managing child processes, as not properly handling child processes
 *          may lead to zombie processes.
 *
 * @see sys_wait(), sys_waitid()
 */
sysret_t sys_waitpid(int32_t pid, int *status, int options)
{
    int ret = -1;
    if (!lwp_user_accessable((void *)status, sizeof(int)))
    {
        return -EFAULT;
    }
    else
    {
        ret = lwp_waitpid(pid, status, options, RT_NULL);
    }
    return ret;
}

/**
 * @brief Gets the thread ID of the calling thread.
 *
 * This function returns the unique thread identifier (thread ID) for the calling thread. The thread ID
 * can be used to uniquely identify the thread within the system and is typically used for debugging,
 * thread management, or scheduling purposes.
 *
 * @return sysret_t   The thread ID of the calling thread. The value is typically a positive integer
 *                     representing the unique ID assigned to the thread. In case of failure, an error code
 *                     may be returned.
 *
 * @note The thread ID returned by this function is unique within the system, and it may be used to
 *       reference or manipulate the specific thread associated with the ID.
 *
 * @see sys_set_tid_address(), sys_thread_self(), sys_thread_create()
 */
sysret_t sys_gettid(void)
{
    return rt_thread_self()->tid;
}

/**
 * @brief Waits for a process to change state.
 *
 * This function suspends the execution of the calling process until one of its child processes terminates
 * or a specified process (identified by `pid`) changes its state. The function returns the process ID of the child
 * process that terminated, and provides information about its exit status and resource usage.
 *
 * @param[in]  pid      The process ID of the child process to wait for. The behavior of this parameter can be one of the following:
 *                      - `pid > 0`: Wait for the child process with the specified PID.
 *                      - `pid == 0`: Wait for any child process in the same process group.
 *                      - `pid == -1`: Wait for any child process (default behavior).
 *                      - `pid < -1`: Wait for any child process in the specified process group.
 *
 * @param[out] status   A pointer to an integer where the exit status of the terminated child process will be stored.
 *                      This status can be interpreted using macros such as `WIFEXITED` or `WIFSIGNALED`.
 *
 * @param[in]  options  Options for the wait operation, which can include:
 *                      - `WNOHANG`: Return immediately if no child has exited.
 *                      - `WUNTRACED`: Return if a child has stopped, but not yet terminated.
 *
 * @param[out] ru       A pointer to a `struct rusage` where resource usage information of the child process will be stored.
 *                      This includes information such as CPU time consumed by the child process.
 *
 * @return sysret_t     Returns the process ID of the terminated child on success. In case of failure, a negative error code is returned.
 *
 * @note This function is useful for monitoring and cleaning up child processes in parent-child relationships.
 *       The `status` value can be further analyzed to determine if the child process terminated normally or due to a signal.
 *
 * @see sys_waitpid(), sys_fork(), sys_exit()
 */
sysret_t sys_wait4(pid_t pid, int *status, int options, struct rusage *ru)
{
    return lwp_waitpid(pid, status, options, ru);
}
