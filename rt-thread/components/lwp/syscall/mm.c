#include "lwp_user_mm.h"

/**
 * @brief Adjusts the end of the data segment (heap) of the calling process.
 *
 * This system call changes the location of the program break, which defines the end of
 * the data segment (heap) of the calling process. It provides a unified interface for adjusting
 * the heap size. The `addr` parameter specifies the new location for the program break.
 *
 * @param addr The new program break location. If `addr` is `NULL`, the current program
 *             break is returned. If a valid address is provided, the program break will
 *             be adjusted to this address. The address must be page-aligned, and changes
 *             must stay within the process's allowed address space.
 *
 * @return On success, returns the new program break.
 *
 * @note This function is typically used to manage heap space in a process. The program
 *       break adjustment can impact memory allocations and deallocations in the heap.
 *
 * @warning The `addr` must be a valid address within the process's allocated memory
 *          space. Attempting to set an invalid program break address may result in
 *          undefined behavior or memory corruption.
 *
 * @see malloc(), free(), sys_sbrk()
 */
rt_base_t sys_brk(void *addr)
{
    return lwp_brk(addr);
}

/**
 * @brief Maps a file or device into memory.
 *
 * This system call implements the `mmap2` system call, which maps a file or device into memory.
 * It provides a way for processes to access file contents directly in memory, bypassing
 * the need for explicit read or write operations. This function supports advanced memory
 * mapping options such as shared or private mappings, specific protection flags, and
 * offset alignment.
 *
 * @param addr The starting address for the memory mapping. If `NULL`, the kernel chooses
 *             the address. If not `NULL`, the address must be page-aligned and meet
 *             platform-specific alignment constraints.
 * @param length The length of the memory mapping in bytes. This value is rounded up to
 *               the nearest page size.
 * @param prot The memory protection flags. Possible values include:
 *             - `PROT_READ`: Pages can be read.
 *             - `PROT_WRITE`: Pages can be written.
 *             - `PROT_EXEC`: Pages can be executed.
 *             - `PROT_NONE`: Pages cannot be accessed.
 *             These flags can be combined using bitwise OR (`|`).
 * @param flags Flags that determine the type and behavior of the mapping. Possible values include:
 *              - `MAP_SHARED`: Updates are visible to other processes that map this file.
 *              - `MAP_PRIVATE`: Updates are not visible to other processes and are not written to the file.
 *              - `MAP_FIXED`: Use the exact address specified in `addr`.
 *              - `MAP_ANONYMOUS`: The mapping is not backed by a file and uses zero-initialized memory.
 * @param fd The file descriptor of the file to map. If `MAP_ANONYMOUS` is set in `flags`,
 *           `fd` is ignored and should be set to `-1`.
 * @param pgoffset The offset in the file where the mapping starts, specified in pages (not bytes).
 *                 This allows finer-grained control over the starting point of the mapping.
 *
 * @return On success, returns a pointer to the mapped memory region.
 *
 * @warning Ensure that the combination of `addr`, `length`, `prot`, `flags`, and `fd` is valid.
 *          Improper use may lead to undefined behavior or memory access violations.
 *
 * @see mmap(), munmap(), msync()
 */
void *sys_mmap2(void *addr, size_t length, int prot,
                int flags, int fd, size_t pgoffset)
{
    sysret_t rc     = 0;
    long     offset = 0;

    /* aligned for user addr */
    if ((rt_base_t)addr & ARCH_PAGE_MASK)
    {
        if (flags & MAP_FIXED)
            rc = -EINVAL;
        else
        {
            offset  = (char *)addr - (char *)RT_ALIGN_DOWN((rt_base_t)addr, ARCH_PAGE_SIZE);
            length += offset;
            addr    = (void *)RT_ALIGN_DOWN((rt_base_t)addr, ARCH_PAGE_SIZE);
        }
    }

    if (rc == 0)
    {
        /* fix parameter passing (both along have same effect) */
        if (fd == -1 || flags & MAP_ANONYMOUS)
        {
            fd = -1;
            /* MAP_SHARED has no effect and treated as nothing */
            flags &= ~MAP_SHARED;
            flags |= MAP_PRIVATE | MAP_ANONYMOUS;
        }
        rc = (sysret_t)lwp_mmap2(lwp_self(), addr, length, prot, flags, fd, pgoffset);
    }

    return rc < 0 ? (char *)rc : (char *)rc + offset;
}

/**
 * @brief Unmaps a memory region previously mapped with mmap or mmap2.
 *
 * This system call implements the `munmap` system call, which removes a mapping
 * for a region of memory that was previously created using `mmap` or `mmap2`.
 *
 * @param addr The starting address of the memory region to unmap. This address
 *             must be page-aligned and refer to a region previously mapped.
 * @param length The length of the memory region to unmap, in bytes. This value
 *               is rounded up to the nearest page size internally if needed.
 *
 * @return On success, returns `0`. On failure, returns error code.
 *
 * @warning
 * - Ensure the specified memory region corresponds to a valid, active mapping.
 *   Providing invalid parameters may result in undefined behavior.
 * - Unmapping a region that is still in use by another thread or process can
 *   cause concurrency issues or data corruption.
 *
 * @see mmap(), mmap2(), msync()
 */
sysret_t sys_munmap(void *addr, size_t length)
{
    return lwp_munmap(lwp_self(), addr, length);
}

/**
 * @brief Changes the size or location of an existing memory mapping.
 *
 * This system call implements the `mremap` system call, allowing the resizing
 * or relocation of a previously created memory mapping. It is typically used
 * to dynamically adjust memory allocation for mapped regions without unmapping
 * and remapping them explicitly.
 *
 * @param old_address The starting address of the existing memory mapping to be resized
 *                    or relocated. This must be the address returned by a previous
 *                    `mmap` or `mremap` call.
 * @param old_size The current size of the memory mapping, in bytes. It must match
 *                 the size of the original mapping.
 * @param new_size The new desired size of the memory mapping, in bytes. The size will
 *                 be rounded up to the nearest page size if necessary.
 * @param flags Options to control the behavior of the remapping. Possible values include:
 *              - `MREMAP_MAYMOVE`: Allows the kernel to move the mapping to a new
 *                address if the current region cannot be resized in place.
 *              - `MREMAP_FIXED`: Requires the mapping to be relocated to the
 *                specified `new_address`. This flag must be used with caution.
 * @param new_address If `MREMAP_FIXED` is set in `flags`, this specifies the address
 *                    for the new mapping. Otherwise, it is ignored.
 *
 * @return On success, returns a pointer to the resized or relocated memory mapping.
 *
 * @warning
 * - Ensure that the `old_address` and `old_size` correspond to a valid, existing mapping.
 *
 * @see mmap(), munmap(), msync()
 */
void *sys_mremap(void *old_address, size_t old_size,
                 size_t new_size, int flags, void *new_address)
{
    return lwp_mremap(lwp_self(), old_address, old_size, new_size, flags, new_address);
}

sysret_t sys_madvise(void *addr, size_t len, int behav)
{
    return -ENOSYS;
}

/**
 * @brief Allocates or retrieves a shared memory segment.
 *
 * This system call allocates a new shared memory segment or retrieves an existing one
 * based on the specified `key`. Shared memory allows processes to communicate by
 * sharing a region of memory.
 *
 * @param[in] key     A unique identifier for the shared memory segment. If `key` matches
 *                    an existing segment, it will be retrieved. If `create` is set and the
 *                    segment does not exist, a new one will be created.
 * @param[in] size    The size (in bytes) of the shared memory segment. If creating a new
 *                    segment, this specifies its size. If retrieving an existing segment,
 *                    `size` is ignored.
 * @param[in] create  A flag indicating whether to create the segment if it does not exist:
 *                    - `1`: Create the shared memory segment if it does not exist.
 *                    - `0`: Only retrieve an existing segment.
 *
 * @return sysret_t   Returns a status code:
 *                    - `0`: The shared memory segment was successfully created or
 *                      retrieved.
 *                    - Other error codes may indicate issues with the shared memory
 *
 * @note Shared memory segments identified by the same `key` are accessible across
 *       processes. Ensure proper synchronization mechanisms (e.g., semaphores) are in
 *       place to manage access to the shared memory.
 *
 * @warning Using a `NULL` or invalid `key` may result in undefined behavior. When creating
 *          a new segment, ensure that `size` is non-zero and meaningful.
 */
sysret_t sys_shmget(size_t key, size_t size, int create)
{
    return lwp_shmget(key, size, create);
}

/**
  * @brief Removes a shared memory segment.
  *
  * This system call removes the specified shared memory segment identified by its `id`.
  * Once removed, the segment will no longer be accessible, and any memory associated
  * with it will be freed. It is typically used to clean up shared memory resources
  * when they are no longer needed.
  *
  * @param[in] id  The identifier of the shared memory segment to be removed. This identifier
  *                was obtained when the segment was created or retrieved using `sys_shmget`.
  *
  * @return sysret_t  Returns a status code:
  *                    - `0`: The shared memory segment was successfully removed.
  *                    - Other error codes may indicate issues with the shared memory removal.
  *
  * @note This function should be called only when all processes that were using the shared
  *       memory segment have finished accessing it. Removing the segment while it is in use
  *       by another process may result in undefined behavior or memory corruption.
  *
  * @warning Ensure that the shared memory segment is no longer needed by any process before
  *          calling this function to avoid premature removal and potential data loss.
  */
sysret_t sys_shmrm(int id)
{
    return lwp_shmrm(id);
}

/**
  * @brief Attaches a shared memory segment to the calling process's address space.
  *
  * This system call maps a shared memory segment identified by `id` into the calling
  * process's address space. The segment can then be accessed using the returned virtual
  * address. If the segment was previously detached or created, it will be made available
  * for reading and writing.
  *
  * @param[in] id         The identifier of the shared memory segment to be attached.
  *                       This identifier was obtained when the segment was created
  *                       or retrieved using `sys_shmget`.
  * @param[in] shm_vaddr  A pointer to the desired virtual address where the shared
  *                       memory segment should be mapped. If `NULL`, the system will
  *                       choose an appropriate address.
  *
  * @return void*        Returns the virtual address where the shared memory segment
  *                      is mapped. On success, this will be the address in the
  *                      calling process's address space. If the attachment fails,
  *                      `NULL` is returned.
  *
  * @note Once the shared memory segment is attached, it can be accessed like any
  *       regular memory, but it should be used with caution, especially in multi-process
  *       environments. Ensure that proper synchronization mechanisms (e.g., semaphores)
  *       are used to manage concurrent access.
  *
  * @warning Ensure that the shared memory segment is properly allocated and not in use
  *          by other processes before attaching it. Passing invalid `id` or an inaccessible
  *          segment may result in undefined behavior.
  */
void *sys_shmat(int id, void *shm_vaddr)
{
    return lwp_shmat(id, shm_vaddr);
}

/**
  * @brief Detaches a shared memory segment from the calling process's address space.
  *
  * This system call detaches the shared memory segment previously attached to the calling
  * process's address space using `sys_shmat`. After calling this function, the shared
  * memory will no longer be accessible via the returned address.
  *
  * @param[in] shm_vaddr  A pointer to the virtual address where the shared memory
  *                       segment was previously mapped. This address was returned
  *                       by the `sys_shmat` function.
  *
  * @return sysret_t      Returns a status code:
  *                       - `0`: The shared memory segment was successfully detached.
  *                       - Other error codes may indicate issues with the detachment process.
  *
  * @note It is important to ensure that no processes are using the shared memory segment
  *       before detaching it. Detaching the segment while it is still being accessed
  *       may lead to undefined behavior.
  *
  * @warning Ensure that `shm_vaddr` corresponds to a valid attached address returned
  *          by `sys_shmat`. Passing an incorrect or uninitialized address may result
  *          in undefined behavior.
  */
sysret_t sys_shmdt(void *shm_vaddr)
{
    return lwp_shmdt(shm_vaddr);
}
