#include "rtdef.h"
#include "lwp_user_mm.h"
#include "rtthread.h"

/**
 * @brief Creates a mailbox for inter-thread or inter-process communication.
 *
 * This system call creates a mailbox object with the specified name and size.
 * The mailbox is used to exchange messages between threads or tasks in a
 * synchronized manner. The mailbox can be used to send and receive messages
 * of a specified size.
 *
 * @param[in] name A string representing the name of the mailbox. If `NULL`,
 *                 the mailbox will be created without a name. Named mailboxes
 *                 can be identified and accessed globally if supported by the system.
 * @param[in] size The size of the mailbox, which determines the maximum number
 *                 of messages that can be stored in the mailbox at any given time.
 * @param[in] flag The behavior of the mailbox. Possible values include:
 *                 - `RT_IPC_FLAG_FIFO`: Messages are handled in a first-in, first-out order.
 *                 - `RT_IPC_FLAG_PRIO`: Messages are handled in priority order.
 *
 * @return rt_mailbox_t Returns a handle to the created mailbox object.
 *                      On failure, returns `-RT_NULL`.
 *
 * @note
 * - The mailbox object must be explicitly deleted using `sys_mb_delete` when it is
 *   no longer needed to free system resources.
 *
 * @warning
 * - Ensure that sufficient system resources (e.g., memory) are available to create
 *   the mailbox. If resources are insufficient, the function will fail.
 * - Named mailboxes can potentially lead to naming conflicts if multiple mailboxes
 *   with the same name are created. Use unique names to avoid such issues.
 *
 * @see sys_mb_delete(), sys_mb_send(), sys_mb_recv()
 */
rt_mailbox_t sys_mb_create(const char *name, rt_size_t size, rt_uint8_t flag)
{
    int          len   = 0;
    rt_mailbox_t mb    = RT_NULL;
    char        *kname = RT_NULL;

    len = lwp_user_strlen(name);
    if (len <= 0)
    {
        return RT_NULL;
    }

    //  kname = (char *)kmem_get(len + 1);
    kname = (char *)rt_malloc(len + 1);
    if (!kname)
    {
        return RT_NULL;
    }

    if (lwp_get_from_user(kname, (void *)name, len + 1) != (len + 1))
    {
        //  kmem_put(kname);
        rt_free(kname);
        return RT_NULL;
    }

    mb = rt_mb_create(kname, size, flag);
    if (lwp_user_object_add(lwp_self(), (rt_object_t)mb) != 0)
    {
        rt_mb_delete(mb);
        mb = NULL;
    }

    //  kmem_put(kname);
    rt_free(kname);

    return mb;
}

/**
 * @brief Deletes a mailbox object.
 *
 * This system call deletes the specified mailbox object, releasing any resources
 * associated with it. After deletion, the mailbox object should not be used.
 *
 * @param[in] mb The handle to the mailbox object to be deleted.
 *               Must be a valid `rt_mailbox_t` object.
 *
 * @return sysret_t Returns a status code indicating the result of the operation:
 *                   - `0` if the operation was successful.
 *                   - An appropriate error code otherwise.
 *
 * @note Ensure that the mailbox is no longer being accessed by any threads or tasks
 *       before calling this function.
 *
 * @warning Deleting a mailbox that is in use or invalid may lead to undefined behavior.
 *
 * @see sys_mb_create(), sys_mb_send(), sys_mb_recv()
 */
sysret_t sys_mb_delete(rt_mailbox_t mb)
{
    return lwp_user_object_delete(lwp_self(), (rt_object_t)mb);
}

/**
 * @brief Sends a message to a mailbox object.
 *
 * This system call posts a message (a single value) to the specified mailbox.
 * If the mailbox is full, the function will return an error code immediately without waiting time.
 *
 * @param[in] mb    The handle to the mailbox object where the message
 *                  will be sent. Must be a valid `rt_mailbox_t` object.
 * @param[in] value The value to be sent to the mailbox. Typically, this
 *                  is a pointer or an integral value that represents
 *                  the message content.
 *
 * @return sysret_t Returns a status code indicating the result of the
 *                   operation:
 *                   - `0` if the message was successfully sent.
 *                   - `-RT_EFULL` if the mailbox is full.
 *                   - An appropriate error code for other failures.
 *
 * @note Ensure the mailbox has been properly initialized before calling
 *       this function. Sending messages to an uninitialized or invalid
 *       mailbox may result in undefined behavior.
 *
 * @warning If the mailbox is full and the function blocks, ensure
 *          proper handling to avoid potential deadlocks.
 *
 * @see sys_mb_create(), sys_mb_recv(), sys_mb_send_wait()
 */
sysret_t sys_mb_send(rt_mailbox_t mb, rt_ubase_t value)
{
    return rt_mb_send(mb, value);
}

/**
 * @brief Sends a message to a mailbox object with a timeout.
 *
 * This system call attempts to post a message (a single value) to the specified mailbox.
 * If the mailbox is full, the function will wait for a specified timeout period
 * for space to become available. If the timeout expires before the message is sent,
 * the function returns an error.
 *
 * @param[in] mb       The handle to the mailbox object where the message
 *                     will be sent. Must be a valid `rt_mailbox_t` object.
 * @param[in] value    The value to be sent to the mailbox. Typically, this
 *                     is a pointer or an integral value representing the
 *                     message content.
 * @param[in] timeout  The maximum time to wait for space to become available
 *                     in the mailbox, in milliseconds.
 *                     - a negative value can be used to wait indefinitely.
 *                     - `0` can be used for non-blocking behavior.
 *
 * @return sysret_t Returns a status code indicating the result of the
 *                   operation:
 *                   - `0` if the message was successfully sent.
 *                   - `-RT_ETIMEOUT` if the operation timed out.
 *                   - `-RT_EFULL` if the mailbox is full and `timeout` is `0`.
 *                   - An appropriate error code for other failures.
 *
 * @note Ensure the mailbox has been properly initialized before calling this function.
 *       Passing an uninitialized or invalid mailbox handle may result in undefined behavior.
 *
 * @warning Using a negative value without appropriate logic may lead to indefinite blocking,
 *          potentially causing deadlocks.
 * @see sys_mb_send()
 */
sysret_t sys_mb_send_wait(rt_mailbox_t mb,
                          rt_ubase_t   value,
                          rt_int32_t   timeout)
{
    return rt_mb_send_wait(mb, value, timeout);
}

/**
 * @brief Receives a message from a mailbox with a timeout.
 *
 * This system call attempts to receive a message from the specified mailbox.
 * If the mailbox is empty, the function will wait for a specified timeout
 * period for a message to arrive. If no message is received within the timeout,
 * an error is returned.
 *
 * @param[in]  mb       The handle to the mailbox object from which the message
 *                      is to be received. Must be a valid `rt_mailbox_t` object.
 * @param[out] value    Pointer to a variable where the received message will
 *                      be stored. Must not be NULL.
 * @param[in]  timeout  The maximum time to wait for a message, in milliseconds.
 *                      - a negative value: Wait indefinitely until a message is available.
 *                      - `0`: Non-blocking mode. If no message is available, return immediately.
 *
 * @return sysret_t Returns a status code indicating the result of the operation:
 *                   - `0`: The message was successfully received.
 *                   - `-RT_ETIMEOUT`: The operation timed out before a message was received.
 *                   - Other error codes may indicate failures.
 *
 * @note Ensure the mailbox is properly initialized and the `value` pointer
 *       is valid before calling this function. Passing an invalid mailbox
 *       or NULL `value` pointer may lead to undefined behavior.
 *
 * @warning Using a negative value without proper safeguards may cause
 *          indefinite blocking, potentially resulting in deadlocks.
 */
sysret_t sys_mb_recv(rt_mailbox_t mb, rt_ubase_t *value, rt_int32_t timeout)
{
    int         ret = 0;
    rt_ubase_t *kvalue;

    if (!lwp_user_accessable((void *)value, sizeof(rt_ubase_t *)))
    {
        return -EFAULT;
    }

    // kvalue = kmem_get(sizeof(rt_ubase_t *));
    kvalue = (rt_ubase_t *)rt_malloc(sizeof(rt_ubase_t *));
    if (kvalue == RT_NULL)
    {
        return -ENOMEM;
    }

    ret = rt_mb_recv(mb, (rt_ubase_t *)kvalue, timeout);
    if (ret == RT_EOK)
    {
        lwp_put_to_user(value, kvalue, sizeof(rt_ubase_t *));
    }

    // kmem_put(kvalue);
    rt_free(kvalue);

    return ret;
}
