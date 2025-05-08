#include "rtdef.h"

#include "lwp_user_mm.h"
#include "rtthread.h"

/**
 * @brief Creates an event object for inter-thread or inter-process communication.
 *
 * @param name A string representing the name of the event. If `NULL`, the event will
 *             be created without a name. Named events can be identified and accessed
 *             globally if supported by the system.
 * @param flag Specifies the behavior of the event. Possible values include:
 *             - `RT_IPC_FLAG_FIFO`: Events are handled in a first-in, first-out order.
 *             - `RT_IPC_FLAG_PRIO`: Events are handled in priority order.
 *
 * @return On success, returns a handle (`rt_event_t`) to the created event. On failure,
 *         returns `-RT_NULL` to indicate that the event could not be created.
 *
 * @note
 * - The event object must be explicitly deleted using `sys_event_delete` when it is
 *   no longer needed to free system resources.
 *
 * @warning
 * - Ensure that sufficient system resources (e.g., memory) are available to create
 *   the event. If resources are insufficient, the function will fail.
 * - Named events can potentially lead to naming conflicts if multiple events with
 *   the same name are created. Use unique names to avoid such issues.
 *
 * @see sys_event_delete(), sys_event_send(), sys_event_recv()
 */
rt_event_t sys_event_create(const char *name, rt_uint8_t flag)
{
    int        len   = 0;
    rt_event_t event = RT_NULL;
    char      *kname = RT_NULL;

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

    event = rt_event_create(kname, flag);
    if (lwp_user_object_add(lwp_self(), (rt_object_t)event) != 0)
    {
        rt_event_delete(event);
        event = NULL;
    }

    //  kmem_put(kname);
    rt_free(kname);

    return event;
}

/**
 * @brief Deletes a system event object.
 *
 * This system call removes the specified system event object, releasing
 * any resources associated with it. After deletion, the event object
 * should not be used.
 *
 * @param[in] event The handle to the event object to be deleted.
 *                  Must be a valid `rt_event_t` object.
 *
 * @return sysret_t Returns a status code indicating the result of the
 *                   operation:
 *                   - `0` if the operation was successful.
 *                   - An appropriate error code otherwise.
 *
 * @note Ensure that the event is no longer being accessed by any
 *       threads or tasks before calling this function.
 *
 * @warning Deleting an event that is in use or invalid may lead to
 *          undefined behavior.
 * @see sys_event_create(), sys_event_send(), sys_event_recv()
 */
sysret_t sys_event_delete(rt_event_t event)
{
    return lwp_user_object_delete(lwp_self(), (rt_object_t)event);
}

/**
 * @brief Sends an event to the specified event object.
 *
 * This system call sends an event to the specified event object, setting
 * the specified bits in the event object's set. The event can be used
 * to signal other threads or tasks that a particular condition has
 * occurred.
 *
 * @param[in] event The handle to the event object to which the event
 *                  will be sent. Must be a valid `rt_event_t` object.
 * @param[in] set The bits to set in the event object's set. The bits
 *                are specified as a bitmask, where each bit represents
 *                a different event condition.
 *
 * @return sysret_t Returns a status code indicating the result of the
 *                   operation:
 *                   - `0` if the operation was successful.
 *                   - An appropriate error code otherwise.
 *
 * @note The event object must be created before sending events to it.
 *
 * @warning Ensure that the event object is valid and has been created
 *          before calling this function.
 * @see sys_event_create(), sys_event_recv()
 */
sysret_t sys_event_send(rt_event_t event, rt_uint32_t set)
{
    return rt_event_send(event, set);
}

/**
 * @brief Receives an event from the specified event object.
 *
 * This system call waits for an event to be received from the specified
 * event object. The function blocks until the specified event bits are
 * set in the event object's set or the specified timeout period has
 * elapsed. If the event is received, the function returns the set of
 * bits that were set in the event object.
 *
 * @param[in] event The handle to the event object from which the event
 *                  will be received. Must be a valid `rt_event_t` object.
 * @param[in] set The bits to wait for in the event object's set. The
 *                bits are specified as a bitmask, where each bit
 *                represents a different event condition.
 * @param[in] opt The options for receiving the event. Possible values
 *                include:
 *                - `EV_EVENT_ANY`: Wait for any of the specified bits
 *                  to be set.
 *                - `EV_EVENT_ALL`: Wait for all of the specified bits
 *                  to be set.
 * @param[in] timeout The maximum time to wait for the event to be
 *                    received, in milliseconds. A value of `0` means
 *                    no waiting (non-blocking), while a negative value
 *                    may indicate an infinite wait.
 * @param[out] recved A pointer to a variable that will receive the set
 *                    of bits that were set in the event object. If the
 *                    event is received, this variable will be updated
 *                    with the set of bits.
 *
 * @return sysret_t Returns a status code indicating the result of the
 *                   operation:
 *                   - `0` if the operation was successful.
 *                   - An appropriate error code otherwise.
 *
 * @note The event object must be created before receiving events from it.
 *
 * @warning Ensure that the event object is valid and has been created
 *          before calling this function.
 * @see sys_event_create(), sys_event_send()
 */
sysret_t sys_event_recv(rt_event_t   event,
                        rt_uint32_t  set,
                        rt_uint8_t   opt,
                        rt_int32_t   timeout,
                        rt_uint32_t *recved)
{
    int         ret = 0;
    rt_uint32_t krecved;

    if ((recved != NULL) && !lwp_user_accessable((void *)recved, sizeof(rt_uint32_t *)))
    {
        return -EFAULT;
    }

    ret = rt_event_recv(event, set, opt, timeout, &krecved);
    if ((ret == RT_EOK) && recved)
    {
        lwp_put_to_user((void *)recved, &krecved, sizeof(rt_uint32_t *));
    }

    return ret;
}
