#include "rtthread.h"
#include "syscall_generic.h"
#include "lwp_user_mm.h"
#include "rtdbg.h"
#include "time.h"
#include "sys/signalfd.h"

struct k_sigaction
{
    void (*handler)(int);
    unsigned long flags;
    void (*restorer)(void);
    unsigned mask[2];
};

/**
 * @brief Changes the action taken by the system on receiving a signal.
 *
 * This system call allows a process to specify how signals should be handled. It allows you to set a
 * new action for a specific signal, retrieve the old action, and define the signal mask that should
 * be applied during the execution of the signal handler.
 *
 * @param[in] sig         The signal number for which the action is to be set or retrieved.
 *                        Signal numbers are typically defined as constants (e.g., `SIGINT`, `SIGTERM`).
 * @param[in] act         A pointer to a `k_sigaction` structure that specifies the new action for the signal.
 *                        If `act` is `NULL`, the signal's action is not changed.
 * @param[out] oact       A pointer to a `k_sigaction` structure where the old action will be stored.
 *                        If `oact` is `NULL`, the old action is not retrieved.
 * @param[in] sigsetsize  The size of the `sigset_t` structure used in `k_sigaction`. This is to ensure the
 *                        compatibility with the signal mask size.
 *
 * @return sysret_t      Returns `0` on success or a negative error code on failure.
 *
 * @note The `k_sigaction` structure allows you to specify the signal handler, signal mask, and flags for
 *       the signal action. It is important to correctly configure the handler to prevent unexpected
 *       behavior in the signal handling process.
 *
 * @warning Be cautious when modifying signal handling behavior, as incorrect configuration may result
 *          in unhandled signals or undefined behavior. Signal handlers should be designed to perform
 *          minimal, safe operations.
 *
 * @see sys_signal(), sys_sigprocmask()
 */
sysret_t sys_sigaction(int sig, const struct k_sigaction *act,
                       struct k_sigaction *oact, size_t sigsetsize)
{
    int                  ret = -RT_EINVAL;
    struct rt_lwp       *lwp;
    struct lwp_sigaction kact, *pkact   = RT_NULL;
    struct lwp_sigaction koact, *pkoact = RT_NULL;

    if (!sigsetsize)
    {
        SET_ERRNO(EINVAL);
        goto out;
    }
    if (sigsetsize > sizeof(lwp_sigset_t))
    {
        sigsetsize = sizeof(lwp_sigset_t);
    }
    if (!act && !oact)
    {
        SET_ERRNO(EINVAL);
        goto out;
    }
    if (oact)
    {
        if (!lwp_user_accessable((void *)oact, sizeof(*oact)))
        {
            SET_ERRNO(EFAULT);
            goto out;
        }
        pkoact = &koact;
    }
    if (act)
    {
        if (!lwp_user_accessable((void *)act, sizeof(*act)))
        {
            SET_ERRNO(EFAULT);
            goto out;
        }
        kact.sa_flags                 = act->flags;
        kact.__sa_handler._sa_handler = act->handler;
        lwp_memcpy(&kact.sa_mask, &act->mask, sigsetsize);
        kact.sa_restorer = act->restorer;
        pkact            = &kact;
    }

    lwp = lwp_self();
    RT_ASSERT(lwp);
    ret = lwp_signal_action(lwp, sig, pkact, pkoact);
    if (ret == 0 && oact)
    {
        lwp_put_to_user(&oact->handler, &pkoact->__sa_handler._sa_handler, sizeof(void (*)(int)));
        lwp_put_to_user(&oact->mask, &pkoact->sa_mask, sigsetsize);
        lwp_put_to_user(&oact->flags, &pkoact->sa_flags, sizeof(int));
        lwp_put_to_user(&oact->restorer, &pkoact->sa_restorer, sizeof(void (*)(void)));
    }
out:
    return (ret < 0 ? GET_ERRNO() : ret);
}

static int mask_command_u2k[] = {
    [SIG_BLOCK]   = LWP_SIG_MASK_CMD_BLOCK,
    [SIG_UNBLOCK] = LWP_SIG_MASK_CMD_UNBLOCK,
    [SIG_SETMASK] = LWP_SIG_MASK_CMD_SET_MASK,
};

/**
 * @brief Sets or retrieves the signal mask for the calling process.
 *
 * This system call allows the caller to block or unblock signals by modifying the signal mask. The signal
 * mask determines which signals are blocked and which signals can be delivered to the process. The
 * function can also be used to retrieve the current signal mask.
 *
 * @param[in] how      The action to be taken on the signal mask. It can be one of the following values:
 *                     - `SIG_BLOCK`: Add the signals in `sigset` to the current mask.
 *                     - `SIG_UNBLOCK`: Remove the signals in `sigset` from the current mask.
 *                     - `SIG_SETMASK`: Set the signal mask to the value in `sigset`, replacing the current mask.
 * @param[in] sigset   A pointer to a `sigset_t` structure that specifies the signals to be blocked or unblocked.
 *                     This parameter is ignored when `how` is `SIG_SETMASK`, in which case `sigset` is used
 *                     as the new signal mask.
 * @param[out] oset    A pointer to a `sigset_t` structure where the previous signal mask will be stored.
 *                     If `oset` is `NULL`, the previous signal mask will not be returned.
 * @param[in] size     The size of the `sigset_t` structure, ensuring compatibility with the signal mask.
 *
 * @return sysret_t   Returns `0` on success or a negative error code on failure.
 *
 * @note Modifying the signal mask prevents signals from being delivered to the process while they are blocked.
 *       Once the signals are unblocked, they will be delivered to the process if they are pending.
 *
 * @warning Be careful when blocking signals, especially critical ones like `SIGKILL`, as it may interfere
 *          with the normal operation of the system. Ensure that signal masks are managed carefully to avoid
 *          missing important signals.
 *
 * @see sys_sigaction(), sys_sigpending()
 */
sysret_t sys_sigprocmask(int how, const sigset_t *sigset, sigset_t *oset, size_t size)
{
    int           ret     = -1;
    lwp_sigset_t *pnewset = RT_NULL, *poldset = RT_NULL;
#ifdef ARCH_MM_MMU
    lwp_sigset_t newset, oldset;
#endif /* ARCH_MM_MMU*/

    if (!size)
    {
        return -EINVAL;
    }
    if (!oset && !sigset)
    {
        return -EINVAL;
    }
    if (size > sizeof(lwp_sigset_t))
    {
        size = sizeof(lwp_sigset_t);
    }
    if (oset)
    {
#ifdef ARCH_MM_MMU
        if (!lwp_user_accessable((void *)oset, size))
        {
            return -EFAULT;
        }
        poldset = &oldset;
#else
        if (!lwp_user_accessable((void *)oset, size))
        {
            return -EFAULT;
        }
        poldset = (lwp_sigset_t *)oset;
#endif
    }
    if (sigset)
    {
        if (!lwp_user_accessable((void *)sigset, size))
        {
            return -EFAULT;
        }
        lwp_get_from_user(&newset, (void *)sigset, size);
        pnewset = &newset;
    }
    ret = lwp_thread_signal_mask(rt_thread_self(), mask_command_u2k[how], pnewset, poldset);
    if (ret < 0)
    {
        return ret;
    }
    if (oset)
    {
        lwp_put_to_user(oset, poldset, size);
    }
    return (ret < 0 ? -EFAULT : ret);
}

/**
 * @brief Retrieves the set of signals that are pending for delivery to the calling process.
 *
 * This system call allows a process to query the set of signals that are pending, i.e., signals that have
 * been sent to the process but have not yet been delivered because the process is blocking those signals
 * or has not yet handled them. The function returns the set of signals that are waiting to be delivered.
 *
 * @param[out] sigset   A pointer to a `sigset_t` structure where the set of pending signals will be stored.
 *                      The `sigset_t` structure will contain the signals that are pending for delivery.
 * @param[in] sigsize   The size of the `sigset_t` structure, used to ensure compatibility with the signal set.
 *
 * @return sysret_t    Returns `0` on success or a negative error code on failure.
 *
 * @note The returned signal set will contain the signals that have been sent to the process but are blocked,
 *       or that are waiting to be handled. These signals will be delivered once they are unblocked or the
 *       process handles them.
 *
 * @warning Be cautious when querying pending signals, as unblocking too many signals at once may lead
 *          to unexpected behavior or a flood of signal deliveries. It's recommended to carefully manage
 *          the signals the process can accept at any given time.
 *
 * @see sys_sigaction(), sys_sigprocmask()
 */
sysret_t sys_sigpending(sigset_t *sigset, size_t sigsize)
{
    sysret_t     ret = 0;
    lwp_sigset_t lwpset;

    /* Verify and Get sigset, timeout */
    if (!sigset || !lwp_user_accessable((void *)sigset, sigsize))
    {
        ret = -EFAULT;
    }
    else
    {
        /* Fit sigset size to lwp set */
        if (sizeof(lwpset) < sigsize)
        {
            LOG_I("%s: sigsize (%lx) extends lwp sigset chunk\n", __func__, sigsize);
            sigsize = sizeof(lwpset);
        }

        lwp_thread_signal_pending(rt_thread_self(), &lwpset);

        if (!lwp_put_to_user(sigset, &lwpset, sigsize))
            RT_ASSERT(0); /* should never happened */
    }

    return ret;
}

/**
 * @brief Waits for a signal to be delivered, with a timeout.
 *
 * This system call allows a process to wait for one of the signals specified in the `sigset` to be delivered.
 * The process will block until a signal in the set is received or the specified timeout period expires.
 * If the signal is received before the timeout, information about the signal will be returned in the `siginfo_t` structure.
 * If the timeout expires without any signal being delivered, the function will return with an appropriate error code.
 *
 * @param[in] sigset   A pointer to a `sigset_t` structure that specifies the set of signals to wait for.
 *                     The function will block until a signal in this set is received, or the timeout expires.
 * @param[out] info    A pointer to a `siginfo_t` structure where information about the delivered signal will be stored.
 *                     If no signal is received before the timeout, this structure will not be filled.
 * @param[in] timeout  A pointer to a `timespec` structure that specifies the maximum amount of time to wait
 *                     for a signal to be delivered. If this value is `NULL`, the function will wait indefinitely.
 * @param[in] sigsize  The size of the `sigset_t` structure, ensuring compatibility with the signal set.
 *
 * @return sysret_t   Returns `0` on success or a negative error code on failure.
 *
 * @note If the `timeout` is `NULL`, the function will block indefinitely until a signal is delivered.
 *       If a signal is received, the corresponding information is returned in the `siginfo_t` structure.
 *       The `sigset` should contain only the signals you are interested in.
 *
 * @warning If the timeout expires, no signal will be delivered, and the function will return a timeout error.
 *          Make sure to handle the timeout case correctly to prevent any unexpected behavior.
 *
 * @see sys_sigaction(), sys_sigtimedwait()
 */
sysret_t sys_sigtimedwait(const sigset_t *sigset, siginfo_t *info, const struct timespec *timeout, size_t sigsize)
{
    int              sig;
    size_t           ret;
    lwp_sigset_t     lwpset;
    siginfo_t        kinfo;
    struct timespec  ktimeout;
    struct timespec *ptimeout;

    /* for RT_ASSERT */
    RT_UNUSED(ret);

    /* Fit sigset size to lwp set */
    if (sizeof(lwpset) < sigsize)
    {
        LOG_I("%s: sigsize (%lx) extends lwp sigset chunk\n", __func__, sigsize);
        sigsize = sizeof(lwpset);
    }
    else
    {
        /* if sigset of user is smaller, clear extra space */
        memset(&lwpset, 0, sizeof(lwpset));
    }

    /* Verify and Get sigset, timeout */
    if (!sigset || !lwp_user_accessable((void *)sigset, sigsize))
    {
        return -EFAULT;
    }
    else
    {
        ret = lwp_get_from_user(&lwpset, (void *)sigset, sigsize);
        RT_ASSERT(ret == sigsize);
    }

    if (timeout)
    {
        if (!lwp_user_accessable((void *)timeout, sizeof(*timeout)))
            return -EFAULT;
        else
        {
            ret      = lwp_get_from_user(&ktimeout, (void *)timeout, sizeof(*timeout));
            ptimeout = &ktimeout;
            RT_ASSERT(ret == sizeof(*timeout));
        }
    }
    else
    {
        ptimeout = RT_NULL;
    }

    sig = lwp_thread_signal_timedwait(rt_thread_self(), &lwpset, &kinfo, ptimeout);

    if (sig > 0 && info)
    {
        if (!lwp_user_accessable((void *)info, sizeof(*info)))
            return -EFAULT;
        else
        {
            ret = lwp_put_to_user(info, &kinfo, sizeof(*info));
            RT_ASSERT(ret == sizeof(*info));
        }
    }

    return sig;
}

/**
 * @brief Sends a signal to a specific thread.
 *
 * This system call allows a process to send a signal to a specific thread within the same process.
 * The signal specified by the `sig` parameter will be delivered to the thread with the ID `tid`.
 * This function is similar to `kill()`, but it targets a specific thread rather than a process.
 *
 * @param[in] tid   The thread ID to which the signal will be sent. This ID identifies the target thread within the same process.
 * @param[in] sig   The signal number to be sent to the specified thread. The signal can be any valid signal number.
 *
 * @return sysret_t Returns `0` on success or a negative error code on failure.
 *
 * @note The `sig` parameter must be a valid signal number. It can range from `1` to `31`, or be one of the predefined signal constants like `SIGKILL`, `SIGTERM`, etc.
 *       If the target thread does not exist or is not eligible to receive the signal, the function will fail.
 *
 * @warning If an invalid signal number is provided or the target thread does not exist, an error will be returned.
 *          Be careful when sending signals, as some signals (e.g., `SIGKILL`) can immediately terminate the target thread.
 *
 * @see sys_kill(), sys_sigaction()
 */
sysret_t sys_tkill(int tid, int sig)
{
    rt_thread_t thread;
    sysret_t    ret;

    /**
     * Brief: Match a tid and do the kill
     *
     * Note: Critical Section
     * - the thread (READ. may be released at the meantime; protected by locked)
     */
    thread = lwp_tid_get_thread_and_inc_ref(tid);
    ret    = lwp_thread_signal_kill(thread, sig, SI_USER, 0);
    lwp_tid_dec_ref(thread);

    return ret;
}

/**
 * @brief Manipulates the signal mask for the current thread.
 *
 * This function allows a thread to modify its signal mask, which controls which signals are blocked (prevented from delivery).
 * The signal mask can be modified by adding, removing, or setting the signal set as a whole, depending on the `how` parameter.
 * The `sigset` specifies the signals to be manipulated, and the current signal mask before modification can be retrieved in `oset`.
 *
 * @param[in] how     The operation to perform on the signal mask. It can be one of the following values:
 *                    - `SIG_BLOCK`: Add the signals in `sigset` to the current mask (block those signals).
 *                    - `SIG_UNBLOCK`: Remove the signals in `sigset` from the current mask (unblock those signals).
 *                    - `SIG_SETMASK`: Set the signal mask to the signals specified in `sigset` (replace the current mask).
 * @param[in] sigset  A pointer to an `lwp_sigset_t` structure that specifies the set of signals to be manipulated.
 *                    Signals in this set will be added, removed, or set in the current thread's signal mask based on the `how` parameter.
 * @param[out] oset   A pointer to an `lwp_sigset_t` structure where the previous signal mask will be stored.
 *                    This allows the caller to restore the previous mask if needed.
 * @param[in] size    The size of the `lwp_sigset_t` structure. This ensures that the correct structure size is used during signal mask manipulation.
 *
 * @return sysret_t   Returns `0` on success or a negative error code on failure.
 *
 * @note The `sigset` structure should contain only valid signal numbers. If `how` is `SIG_SETMASK`, the entire signal mask will be replaced by the contents of `sigset`.
 *       If `how` is `SIG_BLOCK` or `SIG_UNBLOCK`, the signals in `sigset` will be added or removed from the current mask, respectively.
 *
 * @warning Be cautious when modifying the signal mask, as blocking signals can cause the thread to miss important signals.
 *          If a signal is blocked, it will not be delivered to the thread until it is unblocked, or the thread is explicitly made to handle it.
 *
 * @see sys_sigaction(), sys_thread_sigpending()
 */
sysret_t sys_thread_sigprocmask(int how, const lwp_sigset_t *sigset, lwp_sigset_t *oset, size_t size)
{
    int           ret     = -1;
    lwp_sigset_t *pnewset = RT_NULL, *poldset = RT_NULL;
    lwp_sigset_t  newset, oldset;

    if (!size)
    {
        return -EINVAL;
    }
    if (!oset && !sigset)
    {
        return -EINVAL;
    }
    if (size != sizeof(lwp_sigset_t))
    {
        return -EINVAL;
    }
    if (oset)
    {
        if (!lwp_user_accessable((void *)oset, size))
        {
            return -EFAULT;
        }
    }
    if (sigset)
    {
        if (!lwp_user_accessable((void *)sigset, size))
        {
            return -EFAULT;
        }
        lwp_get_from_user(&newset, (void *)sigset, sizeof(lwp_sigset_t));
        pnewset = &newset;
    }

    ret = lwp_thread_signal_mask(rt_thread_self(), mask_command_u2k[how], pnewset, poldset);
    if (ret < 0)
    {
        return ret;
    }

    if (oset)
    {
        lwp_put_to_user(oset, poldset, sizeof(lwp_sigset_t));
    }
    return (ret < 0 ? -EFAULT : ret);
}

/**
 * @brief Set the value of an interval timer.
 *
 * This function is used to set the value of a specified timer that generates periodic signals
 * after the specified intervals. The timer can be configured to generate a signal when it expires,
 * and it can be used for tasks like scheduling periodic events.
 *
 * @param[in] which Specifies which timer to set. Possible values include:
 *                  - `ITIMER_REAL`: Timer that decrements in real time and sends `SIGALRM` when expired.
 *                  - `ITIMER_VIRTUAL`: Timer that decrements only while the process is executing.
 *                  - `ITIMER_PROF`: Timer that decrements while the process is executing or when it is
 *                    executing in the kernel.
 * @param[in] new A pointer to a `struct itimerspec` containing the new value for the timer.
 *                The `itimerspec` structure contains two `timespec` fields: `it_value` for the initial
 *                expiration time and `it_interval` for the interval between successive expirations.
 * @param[out] old A pointer to a `struct itimerspec` where the previous timer values (before the
 *                 timer is set) will be stored.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note If the specified timer is already active, it will be updated with the new values. The timer
 *       will start at the `it_value` time and will repeat at the interval specified in `it_interval`.
 *       If `it_interval` is set to `0`, the timer will not repeat and will only expire once.
 *
 * @see sys_getitimer(), sigaction(), alarm(), setitimer().
 */
sysret_t sys_setitimer(int which, const struct itimerspec * restrict new, struct itimerspec * restrict old)
{
    sysret_t          rc  = 0;
    rt_lwp_t          lwp = lwp_self();
    struct itimerspec new_value_k;
    struct itimerspec old_value_k;

    if (lwp_get_from_user(&new_value_k, (void *)new, sizeof(*new)) != sizeof(*new))
    {
        return -EFAULT;
    }

    rc = lwp_signal_setitimer(lwp, which, &new_value_k, &old_value_k);
    if (old && lwp_put_to_user(old, (void *)&old_value_k, sizeof old_value_k) != sizeof old_value_k)
        return -EFAULT;

    return rc;
}

/**
 * @brief Create a file descriptor for receiving signals.
 *
 * This function creates a file descriptor that can be used to receive signals, similar to how a
 * regular file descriptor is used. The signals specified in the provided signal mask are blocked
 * for the calling thread, and any matching signals will be reported through the file descriptor.
 * This allows signals to be handled in a more controlled, non-interrupt-driven way by using
 * standard I/O operations (e.g., `read()` or `select()`) on the file descriptor.
 *
 * @param[in] fd    A file descriptor associated with the process, typically obtained from
 *                  `sys_signalfd()` or a similar mechanism. If `fd` is `-1`, a new file descriptor
 *                  will be created.
 * @param[in] mask  A pointer to the signal mask (`sigset_t`) that specifies the signals that
 *                  should be received by the file descriptor. Only signals in the mask will be
 *                  reported.
 * @param[in] flags Additional flags to control the behavior of the signalfd. Common flags
 *                  include `O_NONBLOCK` for non-blocking operation.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note The caller must call `read()` on the resulting file descriptor to actually receive signals.
 *       Each read returns a `struct signalfd_siginfo` containing the signal number, and additional
 *       information, such as the signal source and sender.
 *
 * @see sys_read(), sigprocmask(), sigaction(), sigsuspend().
 */
sysret_t sys_signalfd(int fd, const sigset_t *mask, int flags)
{
    int       ret   = 0;
    sigset_t *kmask = RT_NULL;

#ifdef RT_USING_MUSLLIBC
    if (mask == RT_NULL)
        return -EINVAL;

    if (!lwp_user_accessable((void *)mask, sizeof(struct itimerspec)))
    {
        return -EFAULT;
    }

    // kmask = kmem_get(sizeof(struct itimerspec));
    kmask = rt_malloc(sizeof(struct itimerspec));

    if (kmask)
    {
        if (lwp_get_from_user(kmask, (void *)mask, sizeof(struct itimerspec)) != sizeof(struct itimerspec))
        {
            // kmem_put(kmask);
            rt_free(kmask);
            return -EFAULT;
        }

        ret = signalfd(fd, mask, flags);
        // kmem_put(kmask);
        rt_free(kmask);
    }
#endif

    return (ret < 0 ? GET_ERRNO() : ret);
}
