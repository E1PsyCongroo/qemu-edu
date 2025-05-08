#include "rtdef.h"

#include "lwp_user_mm.h"
#include "rtthread.h"

/**
 * @brief Creates a semaphore.
 *
 * This system call creates a new semaphore with the specified `name` and initializes
 * its value. The semaphore is used for synchronizing access to shared resources in
 * concurrent programming. The semaphore's behavior is defined by the value (`value`)
 * and any flags (`flag`) that specify additional properties or settings.
 *
 * @param name The name of the semaphore. This is a string used to identify the semaphore
 *             in the system. The name must be unique if the system requires it for reference.
 * @param value The initial value of the semaphore. The value typically represents the
 *              number of available resources or tokens. The semaphore will be initialized
 *              with this value.
 * @param flag The flag that specifies the attributes or properties of the semaphore.
 *             Flags can be used to define various characteristics of the semaphore,
 *             such as whether it is binary or counting, whether it is shared, etc.
 *
 * @return On success, returns a handle or reference to the created semaphore. On failure,
 *         returns `NULL`.
 *
 * @note Semaphores are commonly used in multithreading and multiprocessing environments
 *       to synchronize access to shared resources and ensure proper order of execution.
 *       The behavior of the semaphore depends on its type and the system's implementation.
 *
 * @warning Ensure that the `name` is unique and appropriate for your system's naming
 *          conventions. Invalid values for `value` or `flag` may lead to errors in semaphore
 *          creation.
 *
 * @see sem_wait(), sem_post(), sem_destroy()
 */
rt_sem_t sys_sem_create(const char *name, rt_uint32_t value, rt_uint8_t flag)
{
    int   len   = 0;
    char *kname = RT_NULL;

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

    rt_sem_t sem = rt_sem_create(kname, value, flag);
    if (lwp_user_object_add(lwp_self(), (rt_object_t)sem) != 0)
    {
        rt_sem_delete(sem);
        sem = NULL;
    }

    // kmem_put(kname);
    rt_free(kname);

    return sem;
}

/**
 * @brief Deletes a semaphore and releases associated resources.
 *
 * This system call deletes an existing semaphore identified by the given handle `sem`.
 * It releases any resources associated with the semaphore and ensures that it is no longer
 * available for further synchronization operations. After deletion, the semaphore handle
 * is invalid and should not be used.
 *
 * @param sem The semaphore handle to be deleted. This handle is obtained when the semaphore
 *            is created using `sys_sem_create()` or similar functions.
 *
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @note Deleting a semaphore is a critical operation that should be performed only when
 *       the semaphore is no longer needed and no tasks are currently waiting or posting
 *       to it. Deleting a semaphore while it is still in use may lead to undefined behavior.
 *
 * @warning Ensure that no tasks are using or blocking on the semaphore before deleting it.
 *          Using a deleted semaphore will result in undefined behavior and potential system errors.
 *
 * @see sys_sem_create(), sem_wait(), sem_post()
 */
sysret_t sys_sem_delete(rt_sem_t sem)
{
    return lwp_user_object_delete(lwp_self(), (rt_object_t)sem);
}

/**
 * @brief Attempts to take (acquire) a semaphore.
 *
 * This system call attempts to acquire a semaphore, blocking the calling task until the
 * semaphore becomes available or the specified timeout expires. If the semaphore is already
 * available, the calling task will immediately take it and proceed. If the semaphore is not
 * available, the task will block until the semaphore becomes available or the timeout period
 * has elapsed. The `time` parameter specifies the maximum amount of time the task will block
 * waiting for the semaphore.
 *
 * @param sem The semaphore handle to be taken. This handle is obtained when the semaphore
 *            is created using `sys_sem_create()` or similar functions.
 * @param time The maximum time to wait for the semaphore to become available. If the semaphore
 *             is not acquired within this time period, the function will return with an error.
 *             A value of `0` means no waiting (non-blocking), while a negative value may indicate
 *             an infinite wait, depending on the system's implementation.
 *
 * @return On success, returns `0` if the semaphore was successfully taken. On failure, returns error code.
 *
 * @warning Ensure that the semaphore handle is valid and has been properly created before
 *          calling this function. If the semaphore is deleted or invalid, the behavior of
 *          this function is undefined.
 *
 * @see sys_sem_create(), sys_sem_delete(), sem_post()
 */
sysret_t sys_sem_take(rt_sem_t sem, rt_int32_t time)
{
    return rt_sem_take_interruptible(sem, time);
}

/**
 * @brief Releases a semaphore and wakes up any waiting tasks.
 *
 * This system call releases a semaphore, incrementing its value and allowing any tasks
 * that are blocked (waiting) on the semaphore to proceed. If there are tasks waiting for
 * the semaphore, one of them will be unblocked and allowed to take the semaphore.
 * The release operation does not block the calling task, and it will return immediately.
 *
 * @param sem The semaphore handle to be released. This handle is obtained when the semaphore
 *            is created using `sys_sem_create()` or similar functions.
 *
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @warning Ensure that the semaphore handle is valid before calling this function. If the semaphore
 *          is deleted or invalid, the behavior of this function is undefined.
 *
 * @see sys_sem_create(), sys_sem_delete(), sys_sem_take()
 */
sysret_t sys_sem_release(rt_sem_t sem)
{
    return rt_sem_release(sem);
}

/**
 * @brief Creates a mutex.
 *
 * This system call creates a new mutex with the specified `name` and initializes it
 * with the given `flag`. The mutex is used for synchronizing access to shared resources
 * between tasks. Mutexes are typically used to ensure that only one task can access
 * a critical section of code or a resource at a time. The `flag` parameter allows
 * for setting certain properties of the mutex, such as whether it is recursive or whether
 * it can be used by multiple tasks.
 *
 * @param name The name of the mutex. This is a string used to uniquely identify the mutex
 *             within the system. The name must be unique if the system requires it.
 * @param flag The flag that specifies the attributes or properties of the mutex. Flags can
 *             define various mutex behaviors, such as whether the mutex is recursive (allows
 *             the same task to lock it multiple times) or whether it can be shared across
 *             different parts of the system.
 *
 * @return On success, returns a handle to the created mutex. On failure, returns `-RT_NULL`.
 *
 * @note Mutexes are typically used to prevent race conditions and ensure mutual exclusion
 *       when multiple tasks or threads are accessing shared resources.
 *
 * @warning Ensure that the `name` is unique and appropriate according to the system's
 *          naming conventions. Invalid values for `flag` or `name` may result in errors.
 *
 * @see sys_mutex_delete(), sys_mutex_lock(), sys_mutex_unlock()
 */
rt_mutex_t sys_mutex_create(const char *name, rt_uint8_t flag)
{
    int        len   = 0;
    char      *kname = RT_NULL;
    rt_mutex_t mutex = RT_NULL;

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

    mutex = rt_mutex_create(kname, flag);
    if (mutex == RT_NULL)
        return RT_NULL;

    if (lwp_user_object_add(lwp_self(), (rt_object_t)mutex) != 0)
    {
        rt_mutex_delete(mutex);
        mutex = RT_NULL;
    }

    // kmem_put(kname);
    rt_free(kname);

    return mutex;
}

/**
 * @brief Deletes a mutex and releases associated resources.
 *
 * This system call deletes an existing mutex identified by the given handle `mutex`.
 * It releases any resources associated with the mutex and ensures that it is no longer
 * available for further synchronization operations. After deletion, the mutex handle
 * becomes invalid and should not be used. This operation also ensures that no tasks
 * can block or attempt to lock the mutex after it has been deleted.
 *
 * @param mutex The mutex handle to be deleted. This handle is obtained when the mutex
 *              is created using `sys_mutex_create()` or similar functions.
 *
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @warning Ensure that the mutex handle is valid before calling this function. Deleting
 *          an already deleted or invalid mutex will result in undefined behavior.
 *
 * @see sys_mutex_create(), sys_mutex_lock(), sys_mutex_unlock()
 */
sysret_t sys_mutex_delete(rt_mutex_t mutex)
{
    return lwp_user_object_delete(lwp_self(), (rt_object_t)mutex);
}

/**
 * @brief Attempts to acquire (lock) a mutex.
 *
 * This system call attempts to acquire a mutex, blocking the calling task until the
 * mutex becomes available or the specified timeout expires. If the mutex is available,
 * the calling task will immediately acquire it and proceed. If the mutex is already locked
 * by another task, the calling task will block until the mutex is released or the timeout
 * period elapses. The `time` parameter specifies the maximum amount of time the task will
 * block while waiting for the mutex.
 *
 * @param mutex The mutex handle to be locked. This handle is obtained when the mutex is
 *              created using `sys_mutex_create()` or similar functions.
 * @param time The maximum time to wait for the mutex to become available. If the mutex
 *             is not acquired within this time period, the function will return an error.
 *             A value of `0` means no waiting (non-blocking), while a negative value may
 *             indicate an infinite wait.
 *
 * @return On success, returns `0` if the mutex was successfully acquired. On failure, returns error code.
 *
 * @warning Ensure that the mutex handle is valid and has been properly created before
 *          calling this function. If the mutex is deleted or invalid, the behavior of
 *          this function is undefined.
 *
 * @see sys_mutex_create(), sys_mutex_delete(), sys_mutex_unlock()
 */
sysret_t sys_mutex_take(rt_mutex_t mutex, rt_int32_t time)
{
    return rt_mutex_take_interruptible(mutex, time);
}

/**
 * @brief Releases (unlocks) a mutex.
 *
 * This system call releases a mutex that was previously acquired (locked) by the calling task.
 * If any other task is waiting for the mutex, one of them will be unblocked and allowed to
 * acquire the mutex. The release operation does not block the calling task, and it will return
 * immediately after unlocking the mutex.
 *
 * @param mutex The mutex handle to be released. This handle is obtained when the mutex is
 *              created using `sys_mutex_create()` or similar functions.
 *
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @warning Ensure that the mutex handle is valid before calling this function. Attempting
 *          to release a mutex that has not been locked or is already released can result
 *          in undefined behavior.
 *
 * @see sys_mutex_create(), sys_mutex_delete(), sys_mutex_take()
 */
sysret_t sys_mutex_release(rt_mutex_t mutex)
{
    return rt_mutex_release(mutex);
}
