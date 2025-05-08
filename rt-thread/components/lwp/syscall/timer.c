#include "rtdef.h"
#include "rtthread.h"
#include "lwp_user_mm.h"

static void timer_timeout_callback(void *parameter)
{
    rt_sem_t sem = (rt_sem_t)parameter;
    rt_sem_release(sem);
}

/**
 * @brief Creates a timer.
 *
 * This system call creates a timer that can be used to trigger events or
 * actions after a specified timeout or interval. The timer will operate in a
 * real-time manner and can be configured to trigger once or repeatedly. The
 * created timer can be started, stopped, or deleted as required.
 *
 * @param[in]  name   The name of the timer. It should be a unique string identifier.
 *                    The name is used for debugging and logging purposes.
 * @param[in]  data   A pointer to user-defined data that will be passed to the timer's
 *                    callback function when it is triggered. This may be used to carry
 *                    context or other necessary information for the callback.
 * @param[in]  period The timer period in milliseconds. The timer will trigger every
 *                    `period` milliseconds, or after the specified timeout.
 * @param[in]  flag   Flags that control the behavior of the timer. These can specify
 *                    whether the timer is one-shot (triggers once) or periodic
 *                    (triggers repeatedly).
 *
 * @return rt_timer_t Returns the handle to the created timer, or `NULL` if the creation failed.
 *
 * @note The timer callback function must be implemented to handle the event triggered
 *       by the timer. Ensure that the `data` parameter, if used, is properly handled
 *       in the callback.
 *
 * @warning Ensure the timer's period and flags are configured correctly to avoid
 *          undesired behavior, especially if the timer is periodic.
 */
rt_timer_t sys_rt_timer_create(const char *name,
                               void *data,
                               rt_tick_t time,
                               rt_uint8_t flag)
{
    int len = 0;
    char *kname = RT_NULL;
    rt_timer_t timer = RT_NULL;

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

    timer = rt_timer_create(kname, timer_timeout_callback, (void *)data, time, flag);
    if (lwp_user_object_add(lwp_self(), (rt_object_t)timer) != 0)
    {
        rt_timer_delete(timer);
        timer = NULL;
    }

    // kmem_put(kname);
    rt_free(kname);

    return timer;
}

/**
 * @brief Deletes a timer.
 *
 * This system call deletes the specified timer and releases any resources
 * associated with it. Once the timer is deleted, its handle becomes invalid,
 * and any further operations on the timer should be avoided.
 *
 * @param[in] timer  The handle to the timer to be deleted. Must be a valid `rt_timer_t` object.
 *
 * @return sysret_t Returns a status code indicating the result of the operation:
 *                   - `0`: The timer was successfully deleted.
 *                   - Other error codes may indicate additional failures.
 *
 * @note Ensure that the timer is not active or being used before deleting it to avoid
 *       any unexpected behavior or resource leaks.
 *
 * @warning Deleting an active timer may lead to undefined behavior, especially
 *          if the timer is in the middle of triggering or executing its callback.
 */
sysret_t sys_rt_timer_delete(rt_timer_t timer)
{
    return lwp_user_object_delete(lwp_self(), (rt_object_t)timer);
}

/**
 * @brief Starts a timer.
 *
 * This system call starts the specified timer, causing it to begin counting down
 * based on its configured period. Once the timer reaches the set period, it triggers the
 * associated callback function. The behavior depends on whether the timer is configured
 * as one-shot or periodic.
 *
 * @param[in] timer  The handle to the timer to be started. Must be a valid `rt_timer_t` object.
 *
 * @return sysret_t  Returns a status code indicating the result of the operation:
 *                    - `0`: The timer was successfully started.
 *                    - Other error codes may indicate additional failures.
 *
 * @note Ensure that the timer has been created and is in a valid state before attempting to start it.
 *
 * @warning Starting a timer that is already running may lead to undefined behavior. Ensure that the
 *          timer is stopped or not in use before starting it.
 */
sysret_t sys_rt_timer_start(rt_timer_t timer)
{
    return rt_timer_start(timer);
}

/**
 * @brief Stops a timer.
 *
 * This system call stops the specified timer, halting its countdown and
 * preventing it from triggering further callbacks. If the timer is periodic,
 * stopping it will prevent further periodic triggers until it is started again.
 *
 * @param[in] timer  The handle to the timer to be stopped. Must be a valid `rt_timer_t` object.
 *
 * @return sysret_t  Returns a status code indicating the result of the operation:
 *                    - `0`: The timer was successfully stopped.
 *                    - Other error codes may indicate additional failures.
 *
 * @note Ensure that the timer is in a valid state before attempting to stop it.
 *       Stopping an inactive or already stopped timer may not have any effect.
 *
 * @warning Stopping a timer that is actively triggering or in use may disrupt its expected
 *          behavior. Ensure proper synchronization or state management when stopping
 *          the timer during active use.
 */
sysret_t sys_rt_timer_stop(rt_timer_t timer)
{
    return rt_timer_stop(timer);
}

/**
 * @brief Controls various properties of a timer.
 *
 * This system call provides control over various aspects of a timer, such as
 * modifying its configuration, querying its status, or changing its behavior.
 * The specific behavior is determined by the command (`cmd`) and any associated arguments (`arg`).
 *
 * @param[in]  timer  The handle to the timer to be controlled. Must be a valid `rt_timer_t` object.
 * @param[in]  cmd    The command to execute. The meaning of this parameter depends on the command value.
 *                    Common commands might include modifying the timer period, changing its callback,
 *                    or querying its current state.
 * @param[in]  arg    A pointer to any additional arguments needed for the command. The type and content
 *                    of this argument depend on the specific command being executed.
 *
 * @return sysret_t  Returns a status code indicating the result of the operation:
 *                    - `0`: The timer control operation was successful.
 *                    - Other error codes may indicate additional failures.
 *
 * @note Ensure that the provided command (`cmd`) is valid for the specific timer implementation.
 *       Incorrect commands or arguments may lead to unexpected behavior or errors.
 *
 * @warning Using invalid or unsupported commands may cause undefined behavior or crashes.
 */
sysret_t sys_rt_timer_control(rt_timer_t timer, int cmd, void *arg)
{
    return rt_timer_control(timer, cmd, arg);
}

/* MUSL compatible */
struct ksigevent
{
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    int sigev_tid;
};

/* to protect unsafe implementation in current rt-smart toolchain */
RT_STATIC_ASSERT(sigevent_compatible, offsetof(struct ksigevent, sigev_tid) == offsetof(struct sigevent, sigev_notify_function));

/**
 * @brief Creates a per-process timer.
 *
 * This system call creates a new timer associated with the specified clock, and
 * initializes the timer with the provided event notification attributes.
 * Once created, the timer can be started, stopped, or controlled as needed.
 * The timer will trigger when the specified expiration time or interval is reached.
 *
 * @param[in]  clockid   The clock to be used for the timer. Common clock values include:
 *                       - `CLOCK_REALTIME`: System real-time clock.
 *                       - `CLOCK_MONOTONIC`: Monotonic clock that cannot be set and is not affected by system time changes.
 *                       - Other clock IDs can be used depending on the platform and requirements.
 * @param[in]  sevp      A pointer to a `sigevent` structure that specifies how the process
 *                       should be notified when the timer expires. This can include notification
 *                       types such as signal delivery, thread notification, or posting to a queue.
 * @param[out] timerid   A pointer to a `timer_t` variable where the created timer's ID will be stored.
 *                       The timer ID will be used for subsequent timer operations (e.g., starting, stopping).
 *
 * @return sysret_t      Returns a status code indicating the result of the operation:
 *                       - `0`: The timer was successfully created.
 *                       - Other error codes may indicate additional failures.
 *
 * @warning Ensure that the provided `sigevent` structure is properly configured, as invalid or
 *          unsupported notification types may result in unexpected behavior.
 */
sysret_t sys_timer_create(clockid_t clockid, struct sigevent *restrict sevp, timer_t *restrict timerid)
{
    int ret = 0;
#ifdef ARCH_MM_MMU
    struct sigevent sevp_k;
    timer_t timerid_k;
    int utimer;

    if (sevp == NULL)
    {
        sevp_k.sigev_notify = SIGEV_SIGNAL;
        sevp_k.sigev_signo = SIGALRM;
        sevp = &sevp_k;
    }
    else
    {
        /* clear extra bytes if any */
        if (sizeof(struct ksigevent) < sizeof(struct sigevent))
            memset(&sevp_k, 0, sizeof(sevp_k));

        /* musl passes `struct ksigevent` to kernel, we shoule only get size of that bytes */
        if (!lwp_get_from_user(&sevp_k, (void *)sevp, sizeof(struct ksigevent)))
        {
            return -EINVAL;
        }
    }

    ret = _SYS_WRAP(timer_create(clockid, &sevp_k, &timerid_k));

    if (ret != -RT_ERROR)
    {
        utimer = (rt_ubase_t)timerid_k;
        if (!lwp_put_to_user(sevp, (void *)&sevp_k, sizeof(struct ksigevent)) ||
            !lwp_put_to_user(timerid, (void *)&utimer, sizeof(utimer)))
            ret = -EINVAL;
    }
#else
    ret = _SYS_WRAP(timer_create(clockid, sevp, timerid));
#endif
    return ret;
}

/**
 * @brief Deletes a timer.
 *
 * This system call deletes the specified timer and releases any resources associated
 * with it. Once the timer is deleted, it can no longer be used, and any further
 * operations on the timer (such as starting or stopping) will result in an error.
 *
 * @param[in] timerid  The ID of the timer to be deleted. This is the timer handle
 *                     returned by `sys_timer_create`.
 *
 * @return sysret_t    Returns a status code indicating the result of the operation:
 *                     - `0`: The timer was successfully deleted.
 *                     - Other error codes may indicate additional failures.
 *
 * @note After calling this function, the timer ID becomes invalid, and it should
 *       not be used in any further operations.
 *
 * @warning Make sure the timer is not active or in use when attempting to delete it,
 *          as deleting an active timer may cause unexpected behavior or resource leaks.
 */
sysret_t sys_timer_delete(timer_t timerid)
{
    int ret = timer_delete(timerid);
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Changes the time or interval of an existing timer.
 *
 * This system call modifies the expiration time or interval of a previously created
 * timer. It can either set a new expiration time for the timer or update the
 * interval for periodic timers. The timer can be started or modified based on
 * the flags provided. The current (old) timer settings can be retrieved if
 * requested.
 *
 * @param[in]  timerid      The ID of the timer to modify. This is the timer handle
 *                          returned by `sys_timer_create`.
 * @param[in]  flags        Flags that control the behavior of the operation. Common
 *                          values include:
 *                          - `TIMER_ABSTIME`: Specifies that `new_value` contains
 *                            an absolute time. Otherwise, it is treated as relative.
 * @param[in]  new_value    A pointer to the `itimerspec` structure specifying
 *                          the new time settings for the timer. The structure includes:
 *                          - `it_value`: The initial expiration time (relative or absolute).
 *                          - `it_interval`: The period for periodic timers.
 * @param[out] old_value    A pointer to an `itimerspec` structure where the previous
 *                          timer settings will be stored. If NULL, the old value is ignored.
 *
 * @return sysret_t         Returns a status code indicating the result of the operation:
 *                          - `0`: The timer time/interval was successfully updated.
 *                          - Other error codes may indicate additional failures.
 *
 * @warning Modifying a timer that is currently active can cause timing-related issues
 *          if not handled correctly. Make sure the timer is in an appropriate state
 *          before making changes.
 */
sysret_t sys_timer_settime(timer_t timerid, int flags,
                           const struct itimerspec *restrict new_value,
                           struct itimerspec *restrict old_value)
{
    int ret = 0;
#ifdef ARCH_MM_MMU
    struct itimerspec new_value_k;
    struct itimerspec old_value_k;

    if (!lwp_get_from_user(&new_value_k, (void *)new_value, sizeof(*new_value)) ||
        (old_value && !lwp_get_from_user(&old_value_k, (void *)old_value, sizeof(*old_value))))
    {
        return -EFAULT;
    }

    ret = timer_settime(timerid, flags, &new_value_k, &old_value_k);
    lwp_put_to_user(old_value, (void *)&old_value_k, sizeof old_value_k);

#else
    ret = timer_settime(timerid, flags, new_value, old_value);
#endif
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Retrieves the current time and interval of a timer.
 *
 * This system call fetches the current expiration time (`it_value`) and interval (`it_interval`)
 * of a previously created timer. It allows the caller to determine the current state of the timer,
 * whether it is one-shot or periodic, and the remaining time before expiration.
 *
 * @param[in]  timerid      The ID of the timer to query. This is the timer handle
 *                          returned by `sys_timer_create`.
 * @param[out] curr_value   A pointer to an `itimerspec` structure where the current timer values
 *                          will be stored. This structure includes:
 *                          - `it_value`: The remaining time until the timer expires.
 *                          - `it_interval`: The interval between subsequent expirations (for periodic timers).
 *
 * @return sysret_t         Returns a status code indicating the result of the operation:
 *                          - `0`: The current time/interval was successfully retrieved.
 *                          - Other error codes may indicate additional failures.
 *
 * @warning Ensure that the timer ID is valid before calling this function, as invalid timer IDs
 *          will result in errors.
 */
sysret_t sys_timer_gettime(timer_t timerid, struct itimerspec *curr_value)
{
    int ret = 0;
#ifdef ARCH_MM_MMU

    struct itimerspec curr_value_k;
    lwp_get_from_user(&curr_value_k, (void *)curr_value, sizeof curr_value_k);
    ret = timer_gettime(timerid, &curr_value_k);
    lwp_put_to_user(curr_value, (void *)&curr_value_k, sizeof curr_value_k);
#else
    ret = timer_gettime(timerid, curr_value);
#endif
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Retrieves the overrun count for a periodic timer.
 *
 * This system call retrieves the number of times a periodic timer has "overrun." An overrun occurs
 * when a timer expires before the previous expiration has been acknowledged or handled. For periodic
 * timers, this indicates how many times the timer's expiration has been missed due to delayed processing
 * or handling.
 *
 * @param[in]  timerid      The ID of the timer to query. This is the timer handle
 *                          returned by `sys_timer_create`.
 *
 * @return sysret_t         Returns a status code indicating the result of the operation:
 *                          - `0`: The overrun count was successfully retrieved.
 *                         - Other error codes may indicate additional failures.
 *
 * @warning Ensure that the timer ID is valid before calling this function, as invalid timer IDs
 *          will result in errors.
 */
sysret_t sys_timer_getoverrun(timer_t timerid)
{
    int ret = 0;
    ret = timer_getoverrun(timerid);
    return (ret < 0 ? GET_ERRNO() : ret);
}