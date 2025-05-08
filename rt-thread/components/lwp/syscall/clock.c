#include "syscall_generic.h"
#include "lwp_user_mm.h"
#include "rtdbg.h"
#include "sys/timerfd.h"

static void *kmem_get(size_t size)
{
    return rt_malloc(size);
}

static void kmem_put(void *kptr)
{
    rt_free(kptr);
}

/**
 * @brief Sets the time of a specified clock.
 *
 * This function sets the time of the specified clock (identified by `clk`) to the given value. The time is provided
 * as a `struct timespec` containing seconds and nanoseconds. This function can be used to set the system clock or
 * other specific clocks, such as monotonic or real-time clocks.
 *
 * @param[in] clk  The clock ID for which to set the time. The clock can be one of the following:
 *                 - `CLOCK_REALTIME`: Set the system's real-time clock.
 *                 - `CLOCK_MONOTONIC`: Set the monotonic clock, which measures time since some unspecified starting point.
 *                 - `CLOCK_PROCESS_CPUTIME_ID`: Set the CPU time used by the process.
 *                 - `CLOCK_THREAD_CPUTIME_ID`: Set the CPU time used by the current thread.
 *
 * @param[in] ts   A pointer to a `struct timespec` containing the new time to set for the specified clock.
 *                 - `ts->tv_sec`: Seconds since the epoch (for `CLOCK_REALTIME`) or since some unspecified start point (for other clocks).
 *                 - `ts->tv_nsec`: Nanoseconds within the current second.
 *
 * @return sysret_t  Returns `0` on success. On failure, returns a negative error code.
 *
 * @note This function requires appropriate permissions for setting the system's clock. In some systems, only privileged users
 *       may change the `CLOCK_REALTIME` clock.
 *
 * @see sys_clock_gettime(), sys_clock_getres()
 */
sysret_t sys_clock_settime(clockid_t clk, const struct timespec *ts)
{
    int              ret  = 0;
    size_t           size = sizeof(struct timespec);
    struct timespec *kts  = NULL;

    if (!lwp_user_accessable((void *)ts, size))
    {
        return -EFAULT;
    }

    kts = kmem_get(size);
    if (!kts)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kts, (void *)ts, size);
    ret = clock_settime(clk, kts);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kts);

    return ret;
}

/**
  * @brief Retrieves the current time of a specified clock.
  *
  * This function retrieves the current time of the specified clock (identified by `clk`) and stores it in the
  * `struct timespec` pointed to by `ts`. The time is expressed in seconds and nanoseconds. The clock can be
  * one of several types, such as real-time, monotonic, or process-specific clocks.
  *
  * @param[in] clk  The clock ID for which to get the time. The clock can be one of the following:
  *                 - `CLOCK_REALTIME`: Get the system's real-time clock.
  *                 - `CLOCK_MONOTONIC`: Get the monotonic clock, which measures time since some unspecified starting point.
  *                 - `CLOCK_PROCESS_CPUTIME_ID`: Get the CPU time used by the process.
  *                 - `CLOCK_THREAD_CPUTIME_ID`: Get the CPU time used by the current thread.
  *
  * @param[out] ts  A pointer to a `struct timespec` where the current time for the specified clock will be stored.
  *                 - `ts->tv_sec`: Seconds since the epoch (for `CLOCK_REALTIME`) or since some unspecified start point (for other clocks).
  *                 - `ts->tv_nsec`: Nanoseconds within the current second.
  *
  * @return sysret_t  Returns `0` on success. On failure, returns a negative error code.
  *
  * @note This function requires appropriate permissions for retrieving certain clocks (e.g., `CLOCK_REALTIME`).
  *
  * @see sys_clock_settime(), sys_clock_getres()
  */
sysret_t sys_clock_gettime(clockid_t clk, struct timespec *ts)
{
    int              ret  = 0;
    size_t           size = sizeof(struct timespec);
    struct timespec *kts  = NULL;

    if (!lwp_user_accessable((void *)ts, size))
    {
        return -EFAULT;
    }

    kts = kmem_get(size);
    if (!kts)
    {
        return -ENOMEM;
    }

    ret = clock_gettime(clk, kts);
    if (ret != -1)
        lwp_put_to_user(ts, kts, size);

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kts);

    return ret;
}

/**
  * @brief Suspends the execution of the calling thread for the specified time duration.
  *
  * This function causes the calling thread to sleep for the specified time duration, which is provided as a
  * `struct timespec` containing seconds and nanoseconds. The sleep is done based on the specified clock (identified by `clk`).
  * If the `flags` parameter is set to `TIMER_ABSTIME`, the specified time represents an absolute time, otherwise,
  * it represents a relative time interval.
  *
  * @param[in] clk   The clock ID for which to perform the sleep. The clock can be one of the following:
  *                  - `CLOCK_REALTIME`: Use the system's real-time clock.
  *                  - `CLOCK_MONOTONIC`: Use the monotonic clock, which measures time since some unspecified starting point.
  *                  - `CLOCK_PROCESS_CPUTIME_ID`: Use the CPU time used by the process.
  *                  - `CLOCK_THREAD_CPUTIME_ID`: Use the CPU time used by the current thread.
  *
  * @param[in] flags The sleep behavior flags. The possible flags are:
  *                  - `0`: The sleep duration is relative to the current time.
  *                  - `TIMER_ABSTIME`: The sleep duration is absolute (measured from the specified clock).
  *
  * @param[in] rqtp  A pointer to a `struct timespec` containing the requested sleep time.
  *                  - `rqtp->tv_sec`: Seconds to sleep.
  *                  - `rqtp->tv_nsec`: Nanoseconds to sleep (0 Ã¢â€°Â¤ `rqtp->tv_nsec` < 1 billion).
  *
  * @param[out] rmtp A pointer to a `struct timespec` where the remaining time will be stored if the sleep is interrupted.
  *                  If the sleep completes successfully, `rmtp` will not be modified.
  *                  - `rmtp->tv_sec`: Remaining seconds.
  *                  - `rmtp->tv_nsec`: Remaining nanoseconds.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note This function can be interrupted by signals. In that case, the remaining time is returned in `rmtp`.
  *       If the sleep is not interrupted, the function returns `SYSRET_OK` when the requested time has passed.
  *
  * @see sys_clock_gettime(), sys_clock_settime(), sys_nanosleep()
  */
sysret_t sys_clock_nanosleep(clockid_t clk, int flags, const struct timespec *rqtp, struct timespec *rmtp)
{
    int ret = 0;
    LOG_D("sys_nanosleep\n");
    if (!lwp_user_accessable((void *)rqtp, sizeof *rqtp))
        return -EFAULT;

    struct timespec rqtp_k;
    struct timespec rmtp_k;

    lwp_get_from_user(&rqtp_k, (void *)rqtp, sizeof rqtp_k);
    ret = clock_nanosleep(clk, flags, &rqtp_k, &rmtp_k);
    if ((ret != -1 || rt_get_errno() == EINTR) && rmtp && lwp_user_accessable((void *)rmtp, sizeof *rmtp))
    {
        lwp_put_to_user(rmtp, (void *)&rmtp_k, sizeof rmtp_k);
        if (ret != 0)
            return -EINTR;
    }
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Get the resolution of the specified clock.
  *
  * This function retrieves the resolution of the specified clock, which is the smallest time interval that the clock can measure.
  * The resolution is returned in a `struct timespec` which contains seconds and nanoseconds.
  *
  * @param[in] clk   The clock ID for which to get the resolution. The clock can be one of the following:
  *                  - `CLOCK_REALTIME`: System's real-time clock.
  *                  - `CLOCK_MONOTONIC`: Monotonic clock (measures time since an unspecified point).
  *                  - `CLOCK_PROCESS_CPUTIME_ID`: CPU time consumed by the current process.
  *                  - `CLOCK_THREAD_CPUTIME_ID`: CPU time consumed by the current thread.
  *
  * @param[out] ts   A pointer to a `struct timespec` where the clock's resolution will be stored.
  *                  - `ts->tv_sec`: The number of seconds in the resolution.
  *                  - `ts->tv_nsec`: The number of nanoseconds in the resolution (0 â‰¤ `ts->tv_nsec` < 1 billion).
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note The resolution may be zero for some clocks, depending on the system's configuration.
  *       A clock's resolution determines the smallest unit of time the clock can measure.
  *
  * @see sys_clock_gettime(), sys_clock_settime(), sys_clock_nanosleep()
  */
sysret_t sys_clock_getres(clockid_t clk, struct timespec *ts)
{
    int ret = 0;
#ifdef ARCH_MM_MMU
    struct timespec kts;
    size_t          size = sizeof(struct timespec);

    if (!lwp_user_accessable((void *)ts, size))
    {
        return -EFAULT;
    }

    ret = clock_getres(clk, &kts);

    if (ret != -1)
        lwp_put_to_user(ts, &kts, size);
#else
    if (!lwp_user_accessable((void *)ts, sizeof(struct timespec)))
    {
        return -EFAULT;
    }
    ret = clock_getres(clk, ts);
#endif
    return (ret < 0 ? GET_ERRNO() : ret);
}

#ifndef LWP_USING_RUNTIME
sysret_t lwp_teardown(struct rt_lwp *lwp, void (*cb)(void))
{
    /* if no LWP_USING_RUNTIME configured */
    return -ENOSYS;
}
#endif

/**
  * @brief Create a timer file descriptor.
  *
  * This function creates a timer that can be used to notify a process after a specified
  * amount of time has passed. The timer is represented by a file descriptor, which can be
  * used with functions such as `read` and `poll` to monitor and retrieve notifications
  * about timer expirations.
  *
  * @param[in] clockid The clock to use for the timer. Possible values include:
  *                    - `CLOCK_REALTIME`: The system's real-time clock.
  *                    - `CLOCK_MONOTONIC`: A clock that cannot be set and is not affected by
  *                      changes in the system time.
  * @param[in] flags   Flags that modify the behavior of the timer. The commonly used values are:
  *                    - `TFD_CLOEXEC`: Set the close-on-exec flag for the file descriptor.
  *                    - `TFD_NONBLOCK`: Set the non-blocking flag for the file descriptor.
  *
  * @return sysret_t On success, returns a non-negative file descriptor that refers to the timer.
  *                   On failure, returns a negative error code.
  *
  * @note The timer created by this function can be used to create periodic or one-shot timers.
  *       The timer can be configured using `timerfd_settime` and notifications can be retrieved
  *       by reading from the returned file descriptor.
  */
sysret_t sys_timerfd_create(int clockid, int flags)
{
    int ret;

    ret = timerfd_create(clockid, flags);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Set or modify the expiration time for a timer.
  *
  * This function is used to arm or re-arm a timer associated with a file descriptor created
  * by `sys_timerfd_create`. It allows setting a new expiration time and can also return
  * the previous timer configuration.
  *
  * @param[in] fd     The file descriptor referring to the timer, which was created using
  *                   `sys_timerfd_create`.
  * @param[in] flags  Flags that modify the behavior of the timer. The commonly used values are:
  *                   - `TFD_TIMER_ABSTIME`: If set, the `new` expiration time is an absolute time.
  *                   - `TFD_TIMER_RELATIVE`: The default behavior, where `new` expiration time is
  *                     a relative time from now.
  * @param[in] new    A pointer to a `struct itimerspec` specifying the new expiration time.
  *                   It contains two fields:
  *                   - `it_value`: The initial expiration time of the timer.
  *                   - `it_interval`: The period of periodic timers (if zero, the timer is one-shot).
  * @param[out] old   A pointer to a `struct itimerspec` where the previous timer configuration
  *                   will be stored. This can be `NULL` if the previous configuration is not needed.
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note This function allows for both one-shot and periodic timers. If the timer is periodic,
  *       it will continue triggering at intervals specified in `it_interval` until canceled or modified.
  *       When a timer expires, the associated file descriptor becomes readable, and the application
  *       can retrieve the expiration event by reading from the file descriptor.
  */
sysret_t sys_timerfd_settime(int fd, int flags, const struct itimerspec *new, struct itimerspec *old)
{
    int                ret  = -1;
    struct itimerspec *knew = RT_NULL;
    struct itimerspec *kold = RT_NULL;

    if (new == RT_NULL)
        return -EINVAL;

    if (!lwp_user_accessable((void *)new, sizeof(struct itimerspec)))
    {
        return -EFAULT;
    }

    knew = kmem_get(sizeof(struct itimerspec));

    if (knew)
    {
        lwp_get_from_user(knew, (void *)new, sizeof(struct itimerspec));

        if (old)
        {
            if (!lwp_user_accessable((void *)old, sizeof(struct itimerspec)))
            {
                kmem_put(knew);
                return -EFAULT;
            }

            kold = kmem_get(sizeof(struct itimerspec));
            if (kold == RT_NULL)
            {
                kmem_put(knew);
                return -ENOMEM;
            }
        }

        ret = timerfd_settime(fd, flags, knew, kold);

        if (old)
        {
            lwp_put_to_user(old, kold, sizeof(*kold));
            kmem_put(kold);
        }

        kmem_put(knew);
    }

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Retrieve the current configuration of a timer.
  *
  * This function is used to obtain the current expiration time and interval of a timer associated
  * with a file descriptor created by `sys_timerfd_create`. It allows querying the current state
  * of the timer, including the time remaining until the next expiration and the period (for periodic timers).
  *
  * @param[in] fd    The file descriptor referring to the timer, which was created using
  *                  `sys_timerfd_create`.
  * @param[out] cur  A pointer to a `struct itimerspec` where the current timer configuration will
  *                  be stored. This structure contains:
  *                  - `it_value`: The time remaining until the timer expires.
  *                  - `it_interval`: The period for periodic timers (zero for one-shot timers).
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note The timer's `it_value` field will contain the time remaining until the next expiration.
  *       If the timer is periodic, the `it_interval` field will contain the period for the next expiration.
  *       If the timer has expired and there is no further interval (for one-shot timers), `it_value` will
  *       contain a value of `0`.
  */
sysret_t sys_timerfd_gettime(int fd, struct itimerspec *cur)
{
    int                ret = -1;
    struct itimerspec *kcur;

    if (cur == RT_NULL)
        return -EINVAL;

    if (!lwp_user_accessable((void *)cur, sizeof(struct itimerspec)))
    {
        return -EFAULT;
    }

    kcur = kmem_get(sizeof(struct itimerspec));

    if (kcur)
    {
        lwp_get_from_user(kcur, cur, sizeof(struct itimerspec));
        ret = timerfd_gettime(fd, kcur);
        lwp_put_to_user(cur, kcur, sizeof(struct itimerspec));
        kmem_put(kcur);
    }

    return (ret < 0 ? GET_ERRNO() : ret);
}
