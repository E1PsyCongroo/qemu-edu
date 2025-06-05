#include "syscall_generic.h"
#define _GNU_SOURCE

#include "lwp_user_mm.h"
#include "sys/utsname.h"
#include "sys/times.h"
#include "rtdbg.h"

/**
 * @brief Retrieves the current time and timezone information.
 *
 * This system call retrieves the current time in seconds and microseconds since
 * the Unix epoch (1970-01-01 00:00:00 UTC) and stores it in the `tp` argument.
 * It also retrieves the timezone information, if requested, and stores it in the
 * `tzp` argument. The time returned is the local time of the system unless
 * UTC is specified.
 *
 * @param tp A pointer to a `struct timeval` where the current time will be stored.
 *           The `struct timeval` contains two fields:
 *           - `tv_sec`: The number of seconds since the Unix epoch.
 *           - `tv_usec`: The number of microseconds past `tv_sec`.
 * @param tzp A pointer to a `struct timezone` where the timezone information will
 *            be stored. This structure contains two fields:
 *            - `tz_minuteswest`: The number of minutes west of UTC.
 *            - `tz_dsttime`: A flag indicating the type of daylight saving time (DST) adjustment.
 *            If `tzp` is `NULL`, timezone information is not provided.
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @note The `struct timeval` represents the current time in seconds and microseconds,
 *       while `struct timezone` provides information on the timezone relative to UTC
 *       and any daylight saving adjustments.
 *
 * @warning Ensure that `tp` and `tzp` are valid pointers before calling the function.
 *          If you don't need timezone information, you can pass `NULL` for `tzp`.
 *
 * @see sys_time(), time(), gettimeofday()
 */
sysret_t sys_gettimeofday(struct timeval *tp, struct timezone *tzp)
{
    struct timeval t_k;

    if (tp)
    {
        if (!lwp_user_accessable((void *)tp, sizeof *tp))
        {
            return -EFAULT;
        }

        t_k.tv_sec  = rt_tick_get() / RT_TICK_PER_SECOND;
        t_k.tv_usec = (rt_tick_get() % RT_TICK_PER_SECOND) * (1000000 / RT_TICK_PER_SECOND);

        lwp_put_to_user(tp, (void *)&t_k, sizeof t_k);
    }

    return 0;
}

/**
  * @brief Sets the system's current time and timezone information.
  *
  * @param tv A pointer to a `struct timeval` that contains the new system time to set.
  *           The `struct timeval` consists of:
  *           - `tv_sec`: The number of seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
  *           - `tv_usec`: The number of microseconds past `tv_sec`.
  * @param tzp A pointer to a `struct timezone` that contains the new timezone settings.
  *            The `struct timezone` consists of:
  *            - `tz_minuteswest`: The number of minutes west of UTC.
  *            - `tz_dsttime`: The type of daylight saving time adjustment.
  *            If `tzp` is `NULL`, the timezone information is not changed.
  * @return On success, returns `0`. On failure, returns error code.
  *
  * @note haven't supported now.
  *
  * @see sys_gettimeofday(), settimeofday(), time()
  */
sysret_t sys_settimeofday(const struct timeval *tv, const struct timezone *tzp)
{
    return 0;
}

rt_weak int syslog_ctrl(int type, char *buf, int len)
{
    return -EINVAL;
}

/**
 * @brief Sends a log message to the system log.
 *
 * This system call sends a message to the system log for recording or debugging purposes.
 *
 * @param[in] type  The type of the log message, typically representing the severity
 *                  or category (e.g., debug, info, warning, error). This should be
 *                  a valid predefined log type.
 * @param[in] buf   A pointer to a buffer containing the log message. Must be a
 *                  null-terminated string and a valid pointer.
 * @param[in] len   The length of the log message to be sent, excluding the null
 *                  terminator. If the length exceeds the system log's limit,
 *                  the message may be truncated.
 *
 * @return sysret_t Returns a status code indicating the result of the operation:
 *                   - `0`: The log message was successfully recorded.
 *                   - Other error codes may indicate additional failures.
 *
 * @note Ensure the log type is a valid predefined value supported by the system.
 *       The buffer must remain valid and accessible during the execution of this function.
 *
 * @warning Sending excessively large or frequent log messages may impact system performance.
 */
sysret_t sys_syslog(int type, char *buf, int len)
{
    char *tmp;
    int   ret = -1;

    if (!lwp_user_accessable((void *)buf, len))
    {
        return -EFAULT;
    }

    tmp = (char *)rt_malloc(len);
    if (!tmp)
    {
        return -ENOMEM;
    }

    ret = syslog_ctrl(type, tmp, len);
    lwp_put_to_user(buf, tmp, len);
    rt_free(tmp);

    return ret;
}

static struct rt_semaphore critical_lock;

static int critical_init(void)
{
    rt_sem_init(&critical_lock, "ct_lock", 1, RT_IPC_FLAG_FIFO);
    return 0;
}
INIT_DEVICE_EXPORT(critical_init);

/**
 * @brief Enters a critical section to prevent context switching or interrupts.
 *
 * @note Critical sections are typically used to protect shared resources or perform
 *       non-interruptible operations. Ensure to exit the critical section as soon as
 *       possible by calling `sys_exit_critical` to avoid system performance degradation
 *       or deadlocks.
 *
 * @warning Failure to exit a critical section (e.g., due to an exception or missing
 *          `sys_exit_critical` call) may lead to system instability or a complete halt.
 */
void sys_enter_critical(void)
{
    rt_sem_take(&critical_lock, RT_WAITING_FOREVER);
}

/**
 * @brief Exits a critical section and restores the system's previous state.
 *
 * @note Exiting the critical section as soon as the protected operation is completed
 *       is essential to avoid performance degradation or system deadlocks. Ensure
 *       that every call to `sys_enter_critical` is matched with a corresponding
 *       `sys_exit_critical` call.
 *
 * @warning Calling this function without a prior `sys_enter_critical` may result
 *          in undefined behavior or system instability. Use carefully in nested
 *          critical sections and ensure proper tracking of critical section depth
 *          if required.
 */
void sys_exit_critical(void)
{
    rt_sem_release(&critical_lock);
}

/* syscall: "sys_log" ret: "int" args: "const char*" "size" */
static int __sys_log_enable = 0;
static int sys_log_enable(int argc, char **argv)
{
    if (argc == 1)
    {
        rt_kprintf("sys_log = %d\n", __sys_log_enable);
        return 0;
    }
    else
    {
        __sys_log_enable = atoi(argv[1]);
    }

    return 0;
}
MSH_CMD_EXPORT_ALIAS(sys_log_enable, sys_log, sys_log 1(enable) / 0(disable));

/**
 * @brief Logs a message to the system logging mechanism.
 *
 * This system call writes a log message to the system log for diagnostic or informational purposes.
 * The message is specified by the `log` parameter, and its size is given by the `size` parameter.
 * The logging mechanism is typically used for tracking system events, debugging, or reporting errors.
 *
 * @param[in] log   A pointer to the message to be logged. The message should be a valid character
 *                  array or string.
 * @param[in] size  The size of the log message in bytes. This specifies the number of bytes to write
 *                  from the `log` buffer.
 *
 * @return sysret_t Returns a status code:
 *                   - `0`: The log message was successfully written.
 *                   - Other error codes may indicate issues with the logging process.
 *
 * @note Ensure that the `log` pointer is valid and points to a properly initialized memory buffer.
 *       Truncation may occur if the logging system has a size limitation. Logging should not be used
 *       in performance-critical paths as it may introduce latency.
 *
 * @warning Passing a `NULL` pointer or an invalid `size` may lead to undefined behavior. Ensure the
 *          logging system is properly initialized before invoking this function.
 */
sysret_t sys_log(const char *log, int size)
{
    char       *klog    = RT_NULL;
    rt_device_t console = RT_NULL;

    if (!lwp_user_accessable((void *)log, size))
        return -EFAULT;

    // klog = kmem_get(size);
    klog = (char *)rt_malloc(size);
    if (klog == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user((void *)klog, (void *)log, size) != size)
    {
        // kmem_put(klog);
        rt_free(klog);
        return -EINVAL;
    }

    console = rt_console_get_device();

    if (console && __sys_log_enable)
    {
        rt_device_write(console, -1, klog, size);
    }

    // kmem_put(klog);
    rt_free(klog);

    return 0;
}

/**
 * @brief Reboot the system.
 *
 * This function initiates a system reboot with a specific reboot type and optional arguments.
 * The reboot process is performed by passing `magic` and `magic2` as security keys to validate the
 * reboot request, along with the desired reboot type (`type`) and optional argument (`arg`) that
 * may contain additional parameters depending on the reboot type.
 *
 * @param[in] magic   A magic number for security validation, typically used to verify that the caller
 *                    has sufficient privileges (e.g., root).
 * @param[in] magic2  A second magic number for additional security verification, used in combination
 *                    with `magic` to validate the reboot request.
 * @param[in] type    The type of reboot to perform, such as `RB_AUTOBOOT`, `RB_HALT`, `RB_RESTART`,
 *                    etc. The exact values may depend on the platform.
 * @param[in] arg     An optional argument for the reboot process. This can provide additional data,
 *                    such as a specific shutdown procedure, depending on the type of reboot.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note This operation is typically available to the system administrator (root) and should be used
 *       with caution as it can cause the system to restart or shut down.
 */
sysret_t sys_reboot(int magic, int magic2, int type, void *arg)
{
    sysret_t rc;
    switch (type)
    {
    /* Hardware reset */
    case RB_AUTOBOOT:
        rc = lwp_teardown(lwp_self(), rt_hw_cpu_reset);
        break;

    /* Stop system and switch power off */
    case RB_POWER_OFF:
        rc = lwp_teardown(lwp_self(), rt_hw_cpu_shutdown);
        break;
    default:
        rc = -ENOSYS;
    }

    return rc;
}

sysret_t sys_get_uid()
{
    return 0;
}

sysret_t sys_get_euid()
{
    return 0;
}

sysret_t sys_getegid()
{
    return 0;
}

/**
 * @brief Set the robust list for the current thread.
 *
 * The `sys_set_robust_list` function sets the robust list for the calling thread. The robust list is
 * a list of `struct robust_list_head` elements that contain information about mutexes or other
 * resources that need to be cleaned up if the thread dies unexpectedly.
 *
 * This function is typically used for thread safety in multi-threaded programs, where robust mutexes
 * can be used to avoid leaving resources in an inconsistent state when a thread is terminated
 * without properly unlocking locks or releasing resources.
 *
 * @param[in] head A pointer to the robust list to be set. This list contains `struct robust_list_head`
 *                 entries which are used by the kernel to maintain information about robust mutexes.
 * @param[in] len The length of the robust list (the number of entries in the list). This should correspond
 *                to the size of the list in memory, generally expressed in bytes.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note The robust list should be set during the initialization of a thread or task, and it may be
 *       used by the kernel to track which mutexes need to be cleaned up in case of failure.
 *       The list may be manipulated using related functions such as `sys_get_robust_list`.
 *
 * @see sys_get_robust_list(), robust_mutex, pthread_mutex, set_robust_list.
 */
sysret_t sys_set_robust_list(struct robust_list_head *head, size_t len)
{
    if (len != sizeof(*head))
        return -EINVAL;

    rt_thread_self()->robust_list = head;
    return 0;
}

/**
  * @brief Get the robust list for the specified thread.
  *
  * The `sys_get_robust_list` function retrieves the robust list associated with the given thread.
  * The robust list contains `struct robust_list_head` entries used by the kernel to manage
  * robust mutexes and other resources that need to be cleaned up if the thread terminates unexpectedly.
  *
  * This function is primarily used to retrieve the robust list for a specific thread, so that
  * the caller can inspect or manipulate the robust list to handle clean-up operations in case
  * the thread exits while holding resources.
  *
  * @param[in] tid The thread ID of the thread whose robust list is to be retrieved.
  *
  * @param[out] head_ptr A pointer to a pointer to `struct robust_list_head`. On success,
  *                      this will point to the robust list for the specified thread.
  *
  * @param[out] len_ptr A pointer to a variable that will hold the length of the robust list
  *                     (i.e., the number of entries in the list).
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note The robust list is used to track mutexes and other resources that need to be cleaned up
  *       if a thread terminates without releasing the resources properly. It is typically used by
  *       the kernel for thread safety and resource management in multi-threaded programs.
  *
  * @see sys_set_robust_list(), robust_mutex, pthread_mutex, get_robust_list.
  */
sysret_t sys_get_robust_list(int tid, struct robust_list_head **head_ptr, size_t *len_ptr)
{
    rt_thread_t              thread;
    size_t                   len;
    struct robust_list_head *head;

    if (!lwp_user_accessable((void *)head_ptr, sizeof(struct robust_list_head *)))
    {
        return -EFAULT;
    }
    if (!lwp_user_accessable((void *)len_ptr, sizeof(size_t)))
    {
        return -EFAULT;
    }

    if (tid == 0)
    {
        thread = rt_thread_self();
        head   = thread->robust_list;
    }
    else
    {
        thread = lwp_tid_get_thread_and_inc_ref(tid);
        if (thread)
        {
            head = thread->robust_list;
            lwp_tid_dec_ref(thread);
        }
        else
        {
            return -ESRCH;
        }
    }

    len = sizeof(*(head));

    if (!lwp_put_to_user(len_ptr, &len, sizeof(size_t)))
        return -EFAULT;
    if (!lwp_put_to_user(head_ptr, &head, sizeof(struct robust_list_head *)))
        return -EFAULT;

    return 0;
}

#define ICACHE (1 << 0)
#define DCACHE (1 << 1)
#define BCACHE (ICACHE | DCACHE)

/**
 * @brief Flush the cache for a specified memory region.
 *
 * This function flushes the cache for a specified memory region. It is commonly used
 * to ensure that the contents of a memory region are written back to the main memory
 * or that stale cache entries are invalidated. The cache operation can be controlled
 * by the `cache` parameter to determine whether to clean or invalidate the cache.
 *
 * @param[in] addr   The starting address of the memory region to flush.
 * @param[in] size   The size of the memory region to flush, in bytes.
 * @param[in] cache  A flag to specify the cache operation:
 *                   - `CACHE_CLEAN`: Clean the cache (write back to memory).
 *                   - `CACHE_INVALIDATE`: Invalidate the cache (discard cached data).
 *                   - `CACHE_FLUSH`: Both clean and invalidate the cache.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note This function is typically used in low-level operations or in systems where
 *       cache coherence between memory and cache is critical.
 */
rt_weak sysret_t sys_cacheflush(void *addr, int size, int cache)
{
    if (!lwp_user_accessable(addr, size))
        return -EFAULT;

    if (((size_t)addr < (size_t)addr + size) && ((size_t)addr >= USER_VADDR_START) && ((size_t)addr + size < USER_VADDR_TOP))
    {
        if ((cache & DCACHE))
        {
            rt_hw_cpu_dcache_clean_and_invalidate(addr, size);
        }

        if ((cache & ICACHE))
        {
            rt_hw_cpu_icache_invalidate(addr, size);
        }

        return 0;
    }
    return -EFAULT;
}

/**
 * @brief Get system information.
 *
 * This function retrieves information about the current system, such as the system name,
 * version, release, architecture, and other details. The information is stored in the
 * `utsname` structure pointed to by the `uts` parameter.
 *
 * @param[out] uts  A pointer to a `utsname` structure where the system information will
 *                  be stored. The structure includes fields such as:
 *                  - `sysname`: Operating system name.
 *                  - `nodename`: Network node hostname.
 *                  - `release`: Operating system release version.
 *                  - `version`: Operating system version.
 *                  - `machine`: Hardware identifier (architecture).
 *
 * @return sysret_t Returns `SYSRET_OK` (0) on success. On failure, returns a negative error code.
 *
 * @note This function provides details about the system environment, which may be useful
 *       for applications needing to adapt to different system configurations.
 *
 * @see sys_gethostname, sys_uname
 */
sysret_t sys_uname(struct utsname *uts)
{
    struct utsname utsbuff = {0};
    int            ret     = 0;
    const char    *machine;

    if (!lwp_user_accessable((void *)uts, sizeof(struct utsname)))
    {
        return -EFAULT;
    }
    rt_strncpy(utsbuff.sysname, "RT-Thread", sizeof(utsbuff.sysname));
    utsbuff.nodename[0] = '\0';
    ret                 = rt_snprintf(utsbuff.release, sizeof(utsbuff.release), "%u.%u.%u",
                                      RT_VERSION_MAJOR, RT_VERSION_MINOR, RT_VERSION_PATCH);
    if (ret < 0)
    {
        return -EIO;
    }
    ret = rt_snprintf(utsbuff.version, sizeof(utsbuff.version), "RT-Thread %u.%u.%u %s %s",
                      RT_VERSION_MAJOR, RT_VERSION_MINOR, RT_VERSION_PATCH, __DATE__, __TIME__);
    if (ret < 0)
    {
        return -EIO;
    }

    machine = rt_hw_cpu_arch();
    rt_strncpy(utsbuff.machine, machine, sizeof(utsbuff.machine));

    utsbuff.domainname[0] = '\0';
    lwp_put_to_user(uts, &utsbuff, sizeof utsbuff);
    return 0;
}

/**
 * @brief Sets the address at which the thread ID is stored.
 *
 * This function sets the address of a variable that will store the thread ID for the calling thread.
 * The specified address `tidptr` will hold the thread's unique identifier. This can be useful for
 * managing thread-specific state or for synchronization mechanisms where the thread's ID needs to be
 * shared or checked by other parts of the system.
 *
 * @param[in] tidptr  A pointer to an integer where the thread ID will be stored. This value will
 *                    hold the calling thread's ID, and it can be accessed to identify the thread
 *                    later. The value of the thread ID can be used in various thread management
 *                    operations.
 *
 * @return sysret_t   Returns `0` on success. On failure, returns a negative error code.
 *
 * @note This function is typically used in systems that require associating a specific address with the
 *       thread ID, often in real-time or embedded systems where managing and accessing thread IDs is
 *       crucial for scheduling or resource allocation.
 *
 * @see sys_get_tid(), sys_thread_self(), sys_thread_create()
 */
sysret_t sys_set_tid_address(int *tidptr)
{
    rt_thread_t thread;

    if (!lwp_user_accessable((void *)tidptr, sizeof(int)))
    {
        return -EFAULT;
    }

    thread                  = rt_thread_self();
    thread->clear_child_tid = tidptr;
    return thread->tid;
}

/**
 * @brief Creates a pipe, a unidirectional data channel.
 *
 * This function creates a pipe, which is a unidirectional data channel used for inter-process communication.
 * The pipe consists of two file descriptors: one for reading from the pipe and one for writing to the pipe.
 * The pipe is used for passing data between processes or threads, typically in a producer-consumer scenario.
 *
 * @param[out] fd  An array of two integers where the file descriptors for the read and write ends of the pipe will be stored.
 *                 - `fd[0]`: The file descriptor for reading from the pipe.
 *                 - `fd[1]`: The file descriptor for writing to the pipe.
 *
 * @return sysret_t   Returns `0` on success. On failure, returns a negative error code.
 *
 * @note The pipe created by this function is typically used for simple communication between processes or threads.
 *       The data written to `fd[1]` can be read from `fd[0]`. After usage, both file descriptors should be closed.
 *
 * @see sys_read(), sys_write(), sys_close(), sys_fork(), sys_execve()
 */
sysret_t sys_pipe(int fd[2])
{
    int ret;
    int kfd[2] = {0, 0};

    if (!lwp_user_accessable((void *)fd, sizeof(int[2])))
    {
        return -EFAULT;
    }

    ret = pipe(kfd);

    lwp_put_to_user((void *)fd, kfd, sizeof(int[2]));

    return (ret < 0 ? GET_ERRNO() : ret);
}

#define RLIMIT_CPU     0
#define RLIMIT_FSIZE   1
#define RLIMIT_DATA    2
#define RLIMIT_STACK   3
#define RLIMIT_CORE    4
#define RLIMIT_RSS     5
#define RLIMIT_NPROC   6
#define RLIMIT_NOFILE  7
#define RLIMIT_MEMLOCK 8
#define RLIMIT_AS      9

sysret_t sys_prlimit64(pid_t                pid,
                       unsigned int         resource,
                       const struct rlimit *new_rlim,
                       struct rlimit       *old_rlim)
{
    struct rlimit krlim = {0};
    int ret = 0;

    if (pid != 0 && pid != lwp_getpid())
        return -EINVAL;

    if (old_rlim)
    {
        if (!lwp_user_accessable((void *)old_rlim, sizeof(struct rlimit)))
            return -EFAULT;
        // printf("sys_prlimit64: resource = %d, old_rlim = %p", resource, old_rlim);
        switch (resource)
        {
            case RLIMIT_STACK: {
                rt_thread_t thread = rt_thread_self();
                if (thread) {
                    krlim.rlim_cur = thread->stack_size;
                    krlim.rlim_max = thread->stack_size * 2;
                } else {
                    krlim.rlim_cur = 8 * 1024 * 1024;
                    krlim.rlim_max = 16 * 1024 * 1024;
                }
                break;
            }

            case RLIMIT_NOFILE: {
                struct dfs_fdtable *fdt = dfs_fdtable_get();
                dfs_file_lock();
                krlim.rlim_cur = fdt->maxfd;
                dfs_file_unlock();
                krlim.rlim_max = DFS_FD_MAX;
                break;
            }
            
            default:
                return -EINVAL;
        }

        lwp_put_to_user((void *)old_rlim, &krlim, sizeof(struct rlimit));
    }

    if (new_rlim)
        return -ENOSYS;

    return ret;
}

/**
 * @brief Get resource limits.
 *
 * This function retrieves the current resource limits for the specified resource type.
 * The resource limit specifies the maximum value for a particular resource that a process or thread can use.
 * The limits are returned in an array `rlim` where:
 * - `rlim[0]` represents the soft limit (the current value).
 * - `rlim[1]` represents the hard limit (the maximum allowable value).
 *
 * @param[in] resource  The resource for which to get the limits. It can be one of the following:
 *                      - `RLIMIT_NOFILE`: Maximum number of file descriptors.
 *
 * @param[out] rlim    An array to store the resource limits. The array should have at least 2 elements:
 *                     - `rlim[0]`: The soft limit for the resource.
 *                     - `rlim[1]`: The hard limit for the resource.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note The limits returned by `sys_getrlimit` are subject to system constraints and may vary across different systems.
 *
 * @see sys_setrlimit(), sys_getrlimit64(), sys_getrusage()
 */
sysret_t sys_getrlimit(unsigned int resource, unsigned long rlim[2])
{
    LOG_I("sys_getrlimit: resource = %d, rlim = %p", resource, rlim);
    int           ret      = -1;
    unsigned long krlim[2] = {0, 0};

    if (!lwp_user_accessable((void *)rlim, sizeof(unsigned long[2])))
    {
        return -EFAULT;
    }

    if (lwp_get_from_user(krlim, rlim, sizeof(unsigned long[2])) != sizeof(unsigned long[2]))
    {
        return -EINVAL;
    }

    switch (resource)
    {
    case RLIMIT_NOFILE: {
        struct dfs_fdtable *fdt = dfs_fdtable_get();

        dfs_file_lock();
        krlim[0] = fdt->maxfd;
        dfs_file_unlock();
        krlim[1] = DFS_FD_MAX;
        ret      = 0;
    }
    break;
    default:
        return -EINVAL;
        break;
    }

    lwp_put_to_user((void *)rlim, krlim, sizeof(unsigned long[2]));

    return (ret < 0 ? GET_ERRNO() : ret);
}

sysret_t sys_setrlimit(unsigned int resource, struct rlimit *rlim)
{
    return -ENOSYS;
}

/**
 * @brief Retrieves the current value of the error code.
 *
 * This function returns the most recent error code set by a system call. The error code is typically set
 * when a system call fails. This function allows users to retrieve the last error that occurred, helping to
 * diagnose issues or handle errors in a more controlled manner.
 *
 * @return sysret_t  The current error code. A value of `0` indicates no error, while a non-zero value
 *                   represents the most recent error. The error codes are system-specific and can
 *                   represent various failure conditions (e.g., `EINVAL`, `ENOMEM`, `EIO`).
 *
 * @note The error code returned is specific to the current thread or process and is typically updated
 *       each time a system call fails. The error code is persistent until it is overwritten by the next
 *       failed system call or explicitly reset.
 *
 * @see sys_set_errno(), sys_perror(), sys_strerror()
 */
sysret_t sys_get_errno(void)
{
    return rt_get_errno();
}

sysret_t sys_memfd_create()
{
    return 0;
}

sysret_t sys_times(void *tms)
{
    struct tms k_tms;

    if (!lwp_user_accessable((void *)tms, sizeof(struct tms)))
    {
        return -EFAULT;
    }

    times(&k_tms);

    lwp_put_to_user(tms, &k_tms, sizeof(struct tms));

    return 0;
}

sysret_t sys_membarrier(int cmd, unsigned int flags, int cpu_id)
{
    #define MEMBARRIER_CMD_QUERY                 0
    #define MEMBARRIER_CMD_GLOBAL                1
    #define MEMBARRIER_CMD_GLOBAL_EXPEDITED      2
    #define MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED 3
    #define MEMBARRIER_CMD_PRIVATE_EXPEDITED     4
    #define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED 5
    #define MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE 6
    #define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE 7

    if (cmd == MEMBARRIER_CMD_QUERY) {
        return (1 << MEMBARRIER_CMD_GLOBAL);
    }

    if (flags != 0) {
        return -EINVAL;
    }

    switch (cmd) {
        case MEMBARRIER_CMD_GLOBAL:
            rt_hw_dmb();
            rt_hw_dsb();
            rt_hw_isb();
            
            #ifdef RT_USING_SMP
            {
                /* Execute IPI to force memory barrier on all other CPUs */
                rt_hw_ipi_send(RT_CPU_MASK_ALL & ~(1 << rt_hw_cpu_id()), RT_SCHEDULE_IPI);
            }
            #endif
            return 0;
            
        default:
            return -EINVAL;
    }
}
