#include "rtdef.h"
#include "lwp.h"
#include "lwp_syscall.h"
#include "lwp_user_mm.h"
#include "lwp_internal.h"
#include "sched.h"
#include "syscall_generic.h"
#include "sys/sysinfo.h"

/**
 * @brief Retrieves the priority of a process or process group.
 *
 * This system call returns the priority of a process or a process group, depending on
 * the value of the `which` argument.
 *
 * @param which The entity for which the priority is being requested. Possible values include:
 *              - `PRIO_PROCESS`: Retrieves the priority of the process specified by `who`.
 *              - `PRIO_PGRP`: Retrieves the priority of the process group specified by `who`. (Currently not supported.)
 *              - `PRIO_USER`: Retrieves the priority of the user specified by `who` (the user ID). (Currently not supported.)
 * @param who The ID of the process, process group, or user. The meaning of this parameter
 *            depends on the value of `which`:
 *            - When `which` is `PRIO_PROCESS`, `who` is the process ID (PID) of the process.
 *            - When `which` is `PRIO_PGRP`(Currently not supported.), `who` is the process group ID (PGID).
 *            - When `which` is `PRIO_USER`(Currently not supported.), `who` is the user ID (UID) of the user whose
 *              priority is being queried.
 * @return On success, returns the priority value (a negative integer indicates a lower
 *         priority).
 *
 * @warning Ensure that `which` and `who` are correctly specified to avoid errors.
 *          Invalid values for `which` or `who` may result in an error, and the function
 *          will return `-1`.
 *
 * @see setpriority(), getpid(), getppid()
 */
sysret_t sys_getpriority(int which, id_t who)
{
    long prio = 0xff;

    if (which == PRIO_PROCESS)
    {
        struct rt_lwp *lwp = RT_NULL;

        lwp_pid_lock_take();
        lwp = lwp_from_pid_locked(who);

        if (lwp)
        {
            rt_thread_t thread = rt_list_entry(lwp->t_grp.prev, struct rt_thread, sibling);
            prio               = RT_SCHED_PRIV(thread).current_priority;
        }

        lwp_pid_lock_release();
    }

    return prio;
}

/**
  * @brief Sets the priority of a process, process group, or user.
  *
  * This system call sets the priority of a process, process group, or user, depending
  * on the value of the `which` argument. The priority is used by the operating system
  * for scheduling processes. Lower numerical values represent higher priority in many
  * systems, and the priority range may be system-specific.
  *
  * @param which The entity for which the priority is being set. Possible values include:
  *              - `PRIO_PROCESS`: Sets the priority of the process specified by `who`.
  *              - `PRIO_PGRP`: Sets the priority of the process group specified by `who`.(Currently not supported.)
  *              - `PRIO_USER`: Sets the priority of the user specified by `who` (the user ID).(Currently not supported.)
  * @param who The ID of the process, process group, or user for which the priority is being set.
  *            The meaning of this parameter depends on the value of `which`:
  *            - When `which` is `PRIO_PROCESS`, `who` is the process ID (PID) of the process.
  *            - When `which` is `PRIO_PGRP`(Currently not supported.)  , `who` is the process group ID (PGID).
  *            - When `which` is `PRIO_USER`(Currently not supported.)  , `who` is the user ID (UID) of the user whose priority
  *              is being set.
  * @param prio The priority value to set.
  * @return On success, returns `0`. On failure, returns `-1`.
  *
  * @note This function modifies the priority of the specified process, process group, or user.
  *       The priority value is system-specific and may vary based on the system's scheduling
  *       policies. Ensure that the specified priority is within the acceptable range.
  *
  * @warning Ensure that `which`, `who`, and `prio` are valid. Invalid values for these
  *          parameters can result in errors, and the system call will return `-1`.
  *
  * @see getpriority(), getpid(), getppid()
  */
sysret_t sys_setpriority(int which, id_t who, int prio)
{
    if (which == PRIO_PROCESS)
    {
        struct rt_lwp *lwp = RT_NULL;

        lwp_pid_lock_take();
        lwp = lwp_from_pid_locked(who);

        if (lwp && prio >= 0 && prio < RT_THREAD_PRIORITY_MAX)
        {
            rt_list_t  *list;
            rt_thread_t thread;
            for (list = lwp->t_grp.next; list != &lwp->t_grp; list = list->next)
            {
                thread = rt_list_entry(list, struct rt_thread, sibling);
                rt_thread_control(thread, RT_THREAD_CTRL_CHANGE_PRIORITY, &prio);
            }
            lwp_pid_lock_release();
            return 0;
        }
        else
        {
            lwp_pid_lock_release();
        }
    }

    return -1;
}

/**
 * @brief Set the CPU affinity mask of a process.
 *
 * This function sets the CPU affinity mask for a specified process. The affinity mask determines which CPUs the
 * process is allowed to execute on. The process will be restricted to the CPUs specified in the mask.
 *
 * @param[in] pid     The process ID of the process whose CPU affinity is to be set. If the `pid` is `0`, the
 *                    affinity of the calling process will be modified.
 * @param[in] size    The size (in bytes) of the CPU set, typically `sizeof(cpu_set_t)`.
 * @param[in] set     A pointer to the CPU set. The CPU set is a bitmask representing which CPUs the process
 *                    is allowed to run on. The bitmask must have enough bits to cover the number of CPUs on the system.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note The CPU set is represented as a bitmask where each bit corresponds to a CPU. If the bit is set, the process
 *       can execute on that CPU. The number of CPUs is platform-dependent, and the size of `set` must be large enough
 *       to hold a bit for each CPU.
 *
 * @see sys_sched_getaffinity(), sys_setcpu()
 */
sysret_t sys_sched_setaffinity(pid_t pid, size_t size, void *set)
{
    void *kset = RT_NULL;

    if (size <= 0 || size > sizeof(cpu_set_t))
    {
        return -EINVAL;
    }
    if (!lwp_user_accessable((void *)set, size))
        return -EFAULT;

    // kset = kmem_get(size);
    kset = rt_malloc(size);
    if (kset == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kset, set, size) != size)
    {
        // kmem_put(kset);
        rt_free(kset);
        return -EINVAL;
    }

    for (int i = 0; i < size * 8; i++)
    {
        if (CPU_ISSET_S(i, size, kset))
        {
            // kmem_put(kset);
            rt_free(kset);

            /**
              * yes it's tricky.
              * But when we talk about 'pid' from GNU libc, it's the 'task-id'
              * aka 'thread->tid' known in kernel.
              */
            return lwp_setaffinity(pid, i);
        }
    }

    // kmem_put(kset);
    rt_free(kset);

    return -1;
}

/**
  * @brief Get the CPU affinity mask of a process.
  *
  * This function retrieves the CPU affinity mask for a specified process. The affinity mask indicates which CPUs the
  * process is allowed to execute on. The process can run on any of the CPUs represented by the bits set in the mask.
  *
  * @param[in]  pid    The process ID of the process whose CPU affinity is to be retrieved. If `pid` is `0`, the
  *                    affinity mask of the calling process will be retrieved.
  * @param[in]  size   The size (in bytes) of the CPU set, typically `sizeof(cpu_set_t)`.
  * @param[out] set    A pointer to a buffer where the CPU affinity mask will be stored. The mask is represented
  *                    as a bitmask, where each bit corresponds to a CPU. The bit is set if the process can run on that CPU.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note The CPU set is represented as a bitmask where each bit corresponds to a CPU. If the bit is set, the process
  *       can execute on that CPU. The number of CPUs is platform-dependent, and the size of `set` must be large enough
  *       to hold a bit for each CPU.
  *
  * @see sys_sched_setaffinity(), sys_getcpu()
  */
sysret_t sys_sched_getaffinity(const pid_t pid, size_t size, void *set)
{
#ifdef ARCH_MM_MMU
    LWP_DEF_RETURN_CODE(rc);
    void          *mask;
    struct rt_lwp *lwp;

    if (size <= 0 || size > sizeof(cpu_set_t))
    {
        return -EINVAL;
    }
    if (!lwp_user_accessable(set, size))
    {
        return -EFAULT;
    }
    // mask = kmem_get(size);
    mask = rt_malloc(size);
    if (!mask)
    {
        return -ENOMEM;
    }

    CPU_ZERO_S(size, mask);

    lwp_pid_lock_take();
    lwp = lwp_from_pid_locked(pid);

    if (!lwp)
    {
        rc = -ESRCH;
    }
    else
    {
#ifdef RT_USING_SMP
        if (lwp->bind_cpu == RT_CPUS_NR) /* not bind */
        {
            for (int i = 0; i < RT_CPUS_NR; i++)
            {
                CPU_SET_S(i, size, mask);
            }
        }
        else /* set bind cpu */
        {
            /* TODO: only single-core bindings are now supported of rt-smart */
            CPU_SET_S(lwp->bind_cpu, size, mask);
        }
#else
        CPU_SET_S(0, size, mask);
#endif

        if (lwp_put_to_user(set, mask, size) != size)
            rc = -EFAULT;
        else
            rc = size;
    }

    lwp_pid_lock_release();

    // kmem_put(mask);
    rt_free(mask);

    LWP_RETURN(rc);
#else
    return -1;
#endif
}

/**
  * @brief Retrieve system information.
  *
  * This function provides details about the current state of the system, such as uptime, memory usage,
  * load average, and other key statistics. The information is stored in a structure pointed to by `info`.
  *
  * @param[out] info A pointer to a buffer where system information will be stored. The structure should
  *                  be compatible with the format expected by the system, typically `struct sysinfo`.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note The structure of `info` must be predefined and consistent with the system's expectations.
  *       This function does not allocate memory for `info`; the caller must provide sufficient
  *       memory for the structure.
  */
sysret_t sys_sysinfo(void *info)
{
#ifdef ARCH_MM_MMU
    struct sysinfo kinfo       = {0};
    rt_size_t      total_pages = 0, free_pages = 0;

    if (!lwp_user_accessable(info, sizeof(struct sysinfo)))
    {
        return -EFAULT;
    }

    kinfo.uptime = rt_tick_get_millisecond() / 1000;
    /* TODO: 1, 5, and 15 minute load averages */
    kinfo.loads[0] = kinfo.loads[1] = kinfo.loads[2] = rt_object_get_length(RT_Object_Class_Thread);
    rt_page_get_info(&total_pages, &free_pages);
    kinfo.totalram = total_pages;
    kinfo.freeram  = free_pages;

    /* TODO: implementation procfs, here is counter the lwp number */
    struct lwp_avl_struct *pids = lwp_get_pid_ary();
    for (int index = 0; index < RT_LWP_MAX_NR; index++)
    {
        struct rt_lwp *lwp = (struct rt_lwp *)pids[index].data;

        if (lwp)
        {
            kinfo.procs++;
        }
    }

    rt_page_high_get_info(&total_pages, &free_pages);
    kinfo.totalhigh = total_pages;
    kinfo.freehigh  = free_pages;
    kinfo.mem_unit  = ARCH_PAGE_SIZE;

    if (lwp_put_to_user(info, &kinfo, sizeof(struct sysinfo)) != sizeof(struct sysinfo))
    {
        return -EFAULT;
    }

    return 0;
#else
    return -1;
#endif
}

/**
  * @brief Set scheduling parameters for a specific thread.
  *
  * This function allows setting the scheduling parameters for a thread identified by its thread ID (`tid`).
  * The parameters are provided via the `param` argument, which should be a structure compatible with the
  * system's scheduling policies.
  *
  * @param[in] tid The thread ID of the target thread for which the scheduling parameters are to be set.
  * @param[in] param A pointer to a structure containing the new scheduling parameters. The structure
  *                  typically includes fields like priority and policy.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note The caller must have appropriate permissions to change the scheduling parameters of the specified thread.
  *       The exact structure and fields of `param` depend on the system's implementation and scheduling policies.
  */
sysret_t sys_sched_setparam(pid_t tid, void *param)
{
    struct sched_param *sched_param = RT_NULL;
    rt_thread_t         thread;
    int                 ret = -1;

    if (!lwp_user_accessable(param, sizeof(struct sched_param)))
    {
        return -EFAULT;
    }

    // sched_param = kmem_get(sizeof(struct sched_param));
    sched_param = rt_malloc(sizeof(struct sched_param));
    if (sched_param == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(sched_param, param, sizeof(struct sched_param)) != sizeof(struct sched_param))
    {
        // kmem_put(sched_param);
        rt_free(sched_param);
        return -EINVAL;
    }

    thread = lwp_tid_get_thread_and_inc_ref(tid);

    if (thread)
    {
        ret = rt_thread_control(thread, RT_THREAD_CTRL_CHANGE_PRIORITY, (void *)&sched_param->sched_priority);
    }

    lwp_tid_dec_ref(thread);

    // kmem_put(sched_param);
    rt_free(sched_param);

    return ret;
}

/**
  * @brief Relinquish the processor voluntarily.
  *
  * This function causes the calling thread to yield the processor, allowing other threads
  * that are ready to run to execute. The thread will be placed back into the scheduler's
  * ready queue and may be rescheduled according to its priority and the system's scheduling policy.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note This function is typically used in cooperative multitasking scenarios or when a thread
  *       explicitly determines it no longer needs the processor at the moment.
  */
sysret_t sys_sched_yield(void)
{
    // rt_thread_yield();
    return 0;
}

/**
  * @brief Retrieve the scheduling parameters of a specific thread.
  *
  * This function retrieves the scheduling parameters of the thread identified by the thread ID (`tid`).
  * The retrieved parameters are stored in the structure pointed to by the `param` argument.
  *
  * @param[in]  tid   The thread ID of the target thread whose scheduling parameters are to be retrieved.
  * @param[out] param A pointer to a structure where the scheduling parameters will be stored. The structure
  *                   typically includes fields like priority and policy.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note The caller must have appropriate permissions to query the scheduling parameters of the specified thread.
  *       The exact structure and fields of `param` depend on the system's implementation and scheduling policies.
  */
sysret_t sys_sched_getparam(const pid_t tid, void *param)
{
    struct sched_param *sched_param = RT_NULL;
    rt_thread_t         thread;
    int                 ret = -1;

    if (!lwp_user_accessable(param, sizeof(struct sched_param)))
    {
        return -EFAULT;
    }

    // sched_param = kmem_get(sizeof(struct sched_param));
    sched_param = rt_malloc(sizeof(struct sched_param));
    if (sched_param == RT_NULL)
    {
        return -ENOMEM;
    }

    thread = lwp_tid_get_thread_and_inc_ref(tid);

    if (thread)
    {
        sched_param->sched_priority = RT_SCHED_PRIV(thread).current_priority;
        ret                         = 0;
    }

    lwp_tid_dec_ref(thread);

    lwp_put_to_user((void *)param, sched_param, sizeof(struct sched_param));
    // kmem_put(sched_param);
    rt_free(sched_param);

    return ret;
}

/**
  * @brief Get the maximum priority for a given scheduling policy.
  *
  * This function retrieves the maximum priority value that can be used with the specified
  * scheduling policy.
  *
  * @param[in] policy The scheduling policy for which to retrieve the maximum priority.
  *
  * @return sysret_t Returns the maximum priority value on success. On failure, returns a
  *                  negative error code.
  *
  * @note The valid priority range depends on the system's configuration and the selected
  *       scheduling policy. The returned value represents the highest priority that can
  *       be assigned to a thread using the given policy.
  */
sysret_t sys_sched_get_priority_max(int policy)
{
    if (policy < 0)
    {
        SET_ERRNO(EINVAL);
        return -rt_get_errno();
    }
    return RT_THREAD_PRIORITY_MAX;
}

/**
  * @brief Get the minimum priority for a given scheduling policy.
  *
  * This function retrieves the minimum priority value that can be used with the specified
  * scheduling policy.
  *
  * @param[in] policy The scheduling policy for which to retrieve the minimum priority.
  *
  * @return sysret_t Returns the minimum priority value on success. On failure, returns a
  *                  negative error code.
  *
  * @note The valid priority range depends on the system's configuration and the selected
  *       scheduling policy. The returned value represents the lowest priority that can
  *       be assigned to a thread using the given policy.
  */
sysret_t sys_sched_get_priority_min(int policy)
{
    if (policy < 0)
    {
        SET_ERRNO(EINVAL);
        return -rt_get_errno();
    }
    return 0;
}

/**
  * @brief Set the scheduling policy and parameters for a thread.
  *
  * This function sets the scheduling policy and associated parameters for the specified thread.
  * It allows controlling the scheduling behavior of threads.
  *
  * @param[in] tid    The thread ID of the target thread.
  * @param[in] policy The scheduling policy to be applied. Common values include:
  *                   - `SCHED_FIFO`: First-in, first-out scheduling.
  *                   - `SCHED_RR`: Round-robin scheduling.
  *                   - `SCHED_OTHER`: Default or standard scheduling.
  * @param[in] param  Pointer to a structure containing scheduling parameters, such as priority.
  *                   The structure type depends on the system implementation.
  *
  * @return sysret_t Returns 0 on success. On failure, returns a negative error code.
  *
  * @note This function requires appropriate permissions to modify the scheduling settings
  *       of another thread. For most systems, elevated privileges may be required.
  *       Ensure the `param` structure is properly initialized for the given `policy`.
  */
sysret_t sys_sched_setscheduler(int tid, int policy, void *param)
{
    sysret_t            ret;
    struct sched_param *sched_param = RT_NULL;
    rt_thread_t         thread      = RT_NULL;

    if (!lwp_user_accessable(param, sizeof(struct sched_param)))
    {
        return -EFAULT;
    }

    // sched_param = kmem_get(sizeof(struct sched_param));
    sched_param = rt_malloc(sizeof(struct sched_param));
    if (sched_param == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(sched_param, param, sizeof(struct sched_param)) != sizeof(struct sched_param))
    {
        // kmem_put(sched_param);
        rt_free(sched_param);
        return -EINVAL;
    }

    thread = lwp_tid_get_thread_and_inc_ref(tid);
    ret    = rt_thread_control(thread, RT_THREAD_CTRL_CHANGE_PRIORITY, (void *)&sched_param->sched_priority);
    lwp_tid_dec_ref(thread);

    // kmem_put(sched_param);
    rt_free(sched_param);

    return ret;
}

/**
  * @brief Get the scheduling policy of a thread.
  *
  * This function retrieves the current scheduling policy of the specified thread.
  *
  * @param[in] tid The thread ID of the target thread.
  *
  * @return sysret_t Returns the scheduling policy of the thread on success. On failure,
  *                  returns a negative error code.
  *
  * @note The caller must have appropriate permissions to query the scheduling policy
  *       of the specified thread.
  */
sysret_t sys_sched_getscheduler(int tid)
{
    rt_thread_t thread = RT_NULL;
    int         rtn;

    thread = lwp_tid_get_thread_and_inc_ref(tid);
    lwp_tid_dec_ref(thread);

    if (thread)
    {
        rtn = SCHED_RR;
    }
    else
    {
        rtn = -ESRCH;
    }

    return rtn;
}
