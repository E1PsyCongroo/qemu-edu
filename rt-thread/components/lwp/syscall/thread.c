#include "rtdef.h"
#include "rtthread.h"
#include "lwp_arch.h"
#include "lwp_user_mm.h"
#include "lwp_internal.h"

#define ALLOC_KERNEL_STACK_SIZE 5120

void lwp_cleanup(struct rt_thread *tid);

static void _crt_thread_entry(void *parameter)
{
    rt_thread_t tid;
    rt_size_t   user_stack;

    tid = rt_thread_self();

    user_stack  = (rt_size_t)tid->user_stack + tid->user_stack_size;
    user_stack &= ~7; /* align 8 */

    arch_crt_start_umode(parameter, tid->user_entry, (void *)user_stack, (char *)tid->stack_addr + tid->stack_size);
}

/**
 * @brief Creates a new thread.
 *
 * This system call creates a new thread within the calling process. The newly created
 * thread starts executing the function specified by the `arg` argument, which typically
 * contains the necessary arguments or function pointer for the thread's execution.
 *
 * @param[in] arg     An array of arguments that will be passed to the function executed
 *                    by the new thread. This can include function pointers, structures,
 *                    or any necessary data the thread will need to execute its work.
 *
 * @return rt_thread_t    Returns a handle to the newly created thread. If the thread
 *                        creation fails, `NULL` is returned.
 *
 * @warning Ensure that the system has sufficient resources to create a new thread.
 *          Thread creation failures can occur if system limits are exceeded or resources
 *          are unavailable.
 */
rt_thread_t sys_thread_create(void *arg[])
{
    void          *user_stack = 0;
    struct rt_lwp *lwp        = 0;
    rt_thread_t    thread     = RT_NULL;
    int            tid        = 0;

    lwp = rt_thread_self()->lwp;
    lwp_ref_inc(lwp);

    user_stack = lwp_map_user(lwp, 0, (size_t)arg[3], 0);
    if (!user_stack)
    {
        goto fail;
    }
    if ((tid = lwp_tid_get()) == 0)
    {
        goto fail;
    }
    thread = rt_thread_create((const char *)arg[0],
                              _crt_thread_entry,
                              (void *)arg[2],
                              ALLOC_KERNEL_STACK_SIZE,
                              (rt_uint8_t)(size_t)arg[4],
                              (rt_uint32_t)(rt_size_t)arg[5]);
    if (!thread)
    {
        goto fail;
    }

#ifdef RT_USING_SMP
    RT_SCHED_CTX(thread).bind_cpu = lwp->bind_cpu;
#endif
    thread->cleanup         = lwp_cleanup;
    thread->user_entry      = (void (*)(void *))arg[1];
    thread->user_stack      = (void *)user_stack;
    thread->user_stack_size = (rt_size_t)arg[3];

    thread->lwp = (void *)lwp;
    thread->tid = tid;
    lwp_tid_set_thread(tid, thread);

    if (lwp->debug)
    {
        rt_thread_control(thread, RT_THREAD_CTRL_BIND_CPU, (void *)0);
    }

    LWP_LOCK(lwp);
    rt_list_insert_after(&lwp->t_grp, &thread->sibling);
    LWP_UNLOCK(lwp);

    return thread;

fail:
    lwp_tid_put(tid);
    if (lwp)
    {
        lwp_ref_dec(lwp);
    }
    return RT_NULL;
}

/**
 * @brief Deletes a thread.
 *
 * This system call is used to delete an existing thread. The specified thread is terminated,
 * and its resources are released. If the thread is currently running, it will be forcefully
 * terminated. The thread identifier (`thread`) refers to the thread that is to be deleted.
 *
 * @param[in] thread   The identifier of the thread to be deleted.
 *
 * @return sysret_t    Returns a status code:
 *                      - `SYSRET_OK`: The thread was successfully deleted.
 *                     - Other error codes may indicate additional failures.
 *
 * @note This function should be used carefully, as forcefully terminating a thread may
 *       lead to resource leaks or inconsistent state if the thread is performing critical
 *       operations at the time of termination.
 *
 * @warning Ensure that the thread being deleted has completed its necessary operations
 *          and that there are no outstanding resources or critical tasks before deleting
 *          it. Otherwise, it might lead to undefined behavior or resource leaks.
 */
sysret_t sys_thread_delete(rt_thread_t thread)
{
    return rt_thread_delete(thread);
}

/**
 * @brief Starts a previously created thread.
 *
 * This system call is used to start a thread that was created but has not yet started running.
 * It initiates the thread's execution, allowing it to begin performing its assigned task.
 * The `thread` parameter refers to the thread that is to be started.
 *
 * @param[in] thread   The identifier of the thread to be started.
 *
 * @return sysret_t    Returns a status code:
 *                      - `0`: The thread was successfully started.
 *                      - Other error codes may indicate additional failures.
 *
 * @warning Ensure that the thread has been correctly initialized and is in a valid state
 *          before calling this function to avoid undefined behavior. Improper initialization
 *          could lead to issues such as the thread not running as expected.
 */
sysret_t sys_thread_startup(rt_thread_t thread)
{
    return rt_thread_startup(thread);
}

/**
 * @brief Retrieves the identifier of the current thread.
 *
 * This system call returns the thread identifier of the currently executing thread. It allows
 * a thread to obtain its own identifier, which can be useful for various thread management
 * tasks such as self-identification, logging, or checking the thread's status.
 *
 * @return rt_thread_t  The identifier of the current thread.
 *                      If no thread is currently executing, a null or invalid thread ID
 *                      might be returned depending on the system's implementation.
 *
 * @note This function is typically used when a thread needs to identify itself, especially
 *       in cases where thread management is performed dynamically or the thread identifier
 *       is required for synchronization or debugging purposes.
 *
 * @warning Be aware that in environments where there is no concept of threads or if the
 *          current context is not a thread (e.g., during interrupt handling or early system
 *          initialization), the return value might be invalid.
 */
rt_thread_t sys_thread_self(void)
{
    return rt_thread_self();
}

uint32_t sys_hw_interrupt_disable(void)
{
    return rt_hw_interrupt_disable();
}

void sys_hw_interrupt_enable(uint32_t level)
{
    rt_hw_interrupt_enable(level);
}

/**
 * @brief Finds a thread by its name.
 *
 * This system call is used to search for a thread based on its name. It returns a reference to the
 * thread if found, otherwise it returns `RT_NULL`. The name comparison is case-sensitive.
 *
 * @param[in] name    The name of the thread to search for. This should be a valid string that
 *                    uniquely identifies the thread within the system.
 *
 * @return rt_thread_t   The thread object corresponding to the given name, or `RT_NULL` if no
 *                        matching thread was found.
 *
 * @note The thread name is typically assigned when the thread is created, and it can be used to
 *       identify threads in the system.
 *
 * @warning Ensure that the `name` string is correctly set and unique within the system to avoid
 *          unexpected behavior.
 *
 * @see sys_thread_create(), sys_thread_delete()
 */
rt_thread_t sys_thread_find(char *name)
{
    int         len   = 0;
    char       *kname = RT_NULL;
    rt_thread_t thread;

    len = lwp_user_strlen(name);
    if (len <= 0)
    {
        return RT_NULL;
    }

    // kname = (char *)kmem_get(len + 1);
    kname = (char *)rt_malloc(len + 1);
    if (!kname)
    {
        return RT_NULL;
    }

    if (lwp_get_from_user(kname, (void *)name, len + 1) != (len + 1))
    {
        // kmem_put(kname);
        rt_free(kname);
        return RT_NULL;
    }

    thread = rt_thread_find(name);

    // kmem_put(kname);
    rt_free(kname);

    return thread;
}

/**
 * @brief Gets the current system tick count.
 *
 * This system call returns the current value of the system tick counter, which is typically incremented
 * at a fixed interval (e.g., every millisecond or microsecond). The tick count can be used for timing
 * purposes, such as measuring the elapsed time or triggering time-based events.
 *
 * @return rt_tick_t    The current value of the system tick counter.
 *
 * @note The system tick counter typically wraps around after reaching its maximum value, so the
 *       returned tick value may reset after a certain period of time, depending on the configuration
 *       of the system tick timer.
 *
 * @warning Be cautious when using the tick value for time-based calculations, as the counter may
 *          overflow and wrap around. Ensure that the code handling the tick count properly accounts
 *          for potential overflow.
 *
 * @see sys_tick_init(), sys_tick_delay()
 */
rt_tick_t sys_tick_get(void)
{
    return rt_tick_get();
}

/**
 * @brief Delays the current thread for a specified number of milliseconds.
 *
 * This system call puts the calling thread to sleep for a given number of milliseconds. It is a blocking
 * call, meaning the thread will not execute any further instructions until the specified delay has
 * passed. The delay is achieved by the system's timer mechanism.
 *
 * @param[in] ms   The number of milliseconds to delay. The value must be a positive integer.
 *
 * @return sysret_t   Returns `0` on success, or a negative error code on failure.
 *
 * @note This function is useful for introducing a fixed delay in time-sensitive applications or when
 *       the thread needs to be paused before continuing execution.
 *
 * @warning Be cautious when using this function in real-time or time-critical applications, as
 *          excessive delays may affect overall system performance or responsiveness.
 *
 * @see sys_thread_delay(), sys_thread_sleep()
 */
sysret_t sys_thread_mdelay(rt_int32_t ms)
{
    return rt_thread_mdelay(ms);
}

/**
 * @brief Sets the thread-specific data area.
 *
 * This function is used to associate a specific area of memory with the current thread. The area pointed to
 * by `p` is set as the thread's local storage. Thread-specific data is used to store data that is unique to
 * each thread, allowing different threads to maintain independent state information.
 *
 * @param[in] p  A pointer to the memory area that is to be set as the thread's local storage. This area
 *               will be used by the thread to store its specific data. The structure and size of the data
 *               area depend on the implementation and use case.
 *
 * @return sysret_t   Returns `0` on success. On failure, it returns a negative error code.
 *
 * @note This function is typically used to set up thread-specific storage for managing data that should
 *       not be shared between threads. The data area is accessible only by the thread that set it, ensuring
 *       thread safety for the stored information.
 *
 * @see sys_get_thread_area(), sys_thread_create(), sys_thread_self()
 */
sysret_t sys_set_thread_area(void *p)
{
    rt_thread_t thread;

    thread             = rt_thread_self();
    thread->thread_idr = p;
    arch_set_thread_area(p);

    return 0;
}
