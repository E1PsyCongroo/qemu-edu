#include "rtconfig.h"
#include "rtthread.h"
#include "rttypes.h"
#include "sys/unistd.h"
#include "syscall_generic.h"
#include "lwp_user_mm.h"

#include "sal_socket.h"
#include "sys/ioctl.h"
#include "sys/epoll.h"
#include "eventfd.h"
#include "dfs_dentry.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#define MAGIC_FD 0xcaffee

static void *kmem_get(size_t size)
{
    return rt_malloc(size);
}

static void kmem_put(void *kptr)
{
    rt_free(kptr);
}

/**
 * @brief Reads data from a file descriptor into a buffer.
 *
 * This system call reads up to `nbyte` bytes of data from the file descriptor
 * specified by `fd` into the buffer pointed to by `buf`.
 *
 * @param fd The file descriptor to read from. This should be a valid file
 *           descriptor obtained through system calls like `open()` or `socket()`.
 * @param buf A pointer to the buffer where the read data will be stored. The buffer
 *            must have enough space to accommodate up to `nbyte` bytes.
 * @param nbyte The maximum number of bytes to read. If the file contains fewer
 *              bytes than `nbyte`, only the available bytes will be read.
 * @return The number of bytes actually read, which may be less than `nbyte` if fewer
 *         bytes are available or if the end of the file is reached. Returns `0` if
 *         the end of the file is encountered. On error, returns `errno`.
 * @warning Ensure the buffer `buf` has sufficient space to hold the requested number
 *          of bytes, as failing to do so may result in undefined behavior.
 */
ssize_t sys_read(int fd, void *buf, size_t nbyte)
{
    void   *kmem = RT_NULL;
    ssize_t ret  = -1;

    if (!nbyte)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)buf, nbyte))
    {
        return -EFAULT;
    }

    kmem = kmem_get(nbyte);
    if (!kmem)
    {
        return -ENOMEM;
    }

    ret = read(fd, kmem, nbyte);
    if (ret > 0)
    {
        if (ret != lwp_put_to_user(buf, kmem, ret))
            return -EFAULT;
    }

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
}

ssize_t sys_readv(int fd, void *user_iovec, int iovcnt)
{
    struct iovec *iovec = kmem_get(sizeof(struct iovec) * iovcnt);
    if (!iovec)
    {
        return -ENOMEM;
    }
    
    // 从用户空间复制 iovec 数组到内核空间
    if (lwp_get_from_user(iovec, user_iovec, sizeof(struct iovec) * iovcnt) != sizeof(struct iovec) * iovcnt)
    {
        kmem_put(iovec);
        return -EFAULT;
    }
    
    ssize_t total_bytes = 0;
    
    // 对每个缓冲区进行处理
    for (int i = 0; i < iovcnt; i++)
    {
        void *buffer;
        
        // 检查用户空间的缓冲区是否可访问
        if (!lwp_user_accessable(iovec[i].iov_base, iovec[i].iov_len))
        {
            kmem_put(iovec);
            return -EFAULT;
        }
        
        // 分配内核缓冲区
        buffer = kmem_get(iovec[i].iov_len);
        if (!buffer)
        {
            kmem_put(iovec);
            return -ENOMEM;
        }
        
        // 读取数据到内核缓冲区
        ssize_t bytes = read(fd, buffer, iovec[i].iov_len);
        if (bytes < 0)
        {
            kmem_put(buffer);
            kmem_put(iovec);
            return GET_ERRNO();
        }
        
        // 如果没有读到任何数据，可能到达了文件末尾
        if (bytes == 0)
        {
            kmem_put(buffer);
            break; // 结束读取循环
        }
        
        // 将读取的数据复制到用户空间
        if (bytes != lwp_put_to_user(iovec[i].iov_base, buffer, bytes))
        {
            kmem_put(buffer);
            kmem_put(iovec);
            return -EFAULT;
        }
        
        // 释放内核缓冲区并累计读取的总字节数
        kmem_put(buffer);
        total_bytes += bytes;
        
        // 如果实际读取的字节数小于请求的字节数，可能表示到达了文件末尾
        if (bytes < (ssize_t)iovec[i].iov_len)
        {
            break;
        }
    }
    
    kmem_put(iovec);
    return total_bytes;
}

/**
  * @brief Writes data from a buffer to a file descriptor.
  *
  * This system call writes up to `nbyte` bytes of data from the buffer pointed
  * to by `buf` to the file descriptor specified by `fd`.
  *
  * @param fd The file descriptor to write to. This should be a valid file
  *           descriptor obtained through system calls like `open()` or `socket()`.
  * @param buf A pointer to the buffer containing the data to be written. The
  *            buffer must remain valid and accessible for the duration of the
  *            write operation.
  * @param nbyte The number of bytes to write from the buffer. If the file descriptor
  *              refers to a device or a socket, the actual number of bytes written
  *              may be less than `nbyte`.
  * @return The number of bytes actually written. This may be less than `nbyte` if
  *         the underlying resource cannot accept more data at the moment. On error,
  *         returns `errno`.
  *
  * @warning Ensure the buffer `buf` contains at least `nbyte` valid bytes to
  *          avoid undefined behavior. Additionally, verify that `fd` is writable
  *          to prevent errors.
  *
  * @see sys_read(), write()
  */
ssize_t sys_write(int fd, const void *buf, size_t nbyte)
{
    if (fd == MAGIC_FD) {
        return 0;
    }

#ifdef ARCH_MM_MMU
    void   *kmem = RT_NULL;
    ssize_t ret  = -1;

    if (nbyte)
    {
        if (!lwp_user_accessable((void *)buf, nbyte))
        {
            return -EFAULT;
        }

        kmem = kmem_get(nbyte);
        if (!kmem)
        {
            return -ENOMEM;
        }

        lwp_get_from_user(kmem, (void *)buf, nbyte);
    }

    ret = write(fd, kmem, nbyte);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
#else
    if (!lwp_user_accessable((void *)buf, nbyte))
    {
        return -EFAULT;
    }
    ssize_t ret = write(fd, buf, nbyte);
    return (ret < 0 ? GET_ERRNO() : ret);
#endif
}

ssize_t sys_writev(int fd, void *user_iovec, int iovcnt)
{
    struct iovec *iovec = kmem_get(sizeof(struct iovec) * iovcnt);
    if (lwp_get_from_user(iovec, user_iovec, sizeof(struct iovec) * iovcnt) != sizeof(struct iovec) * iovcnt)
    {
        return -1;
    }

    ssize_t cnt = 0;
    for (int i = 0; i < iovcnt; i++)
    {
        void *buffer = kmem_get(iovec[i].iov_len);
        lwp_get_from_user(buffer, iovec[i].iov_base, iovec[i].iov_len);
        write(fd, buffer, iovec[i].iov_len);
        kmem_put(buffer);

        cnt += iovec[i].iov_len;
    }

    kmem_put(iovec);

    return cnt;
}

/**
  * @brief Repositions the file offset of the open file descriptor.
  *
  * This system call sets the file offset for the open file descriptor `fd`
  * to a new position based on the `offset` and `whence` parameters. It is used
  * for seeking within files, enabling random access to file content.
  *
  * @param fd The file descriptor whose offset is to be modified. The descriptor
  *           must refer to a file capable of seeking (e.g., regular files, but
  *           not pipes or sockets).
  * @param offset The new offset value relative to the position specified by `whence`.
  *               Can be a positive or negative value, depending on the seek direction.
  * @param whence The reference point for the new offset. Must be one of the following:
  *               - `SEEK_SET`: Set the offset to `offset` bytes from the beginning of the file.
  *               - `SEEK_CUR`: Set the offset to its current position plus `offset`.
  *               - `SEEK_END`: Set the offset to the size of the file plus `offset`.
  * @return On success, returns the resulting offset location as measured in bytes
  *         from the beginning of the file. On failure, returns `errno`.
  *
  * @warning Ensure the file descriptor `fd` supports seeking. Using this function
  *          on non-seekable file descriptors (e.g., pipes or sockets) will result in an error.
  *
  * @see sys_read(), sys_write(), lseek()
  */
size_t sys_lseek(int fd, size_t offset, int whence)
{
    ssize_t ret = lseek(fd, offset, whence);
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Opens or creates a file, returning a file descriptor.
  *
  * This system call opens the file specified by `name` with the specified
  * access mode and flags. If the file does not exist and the `O_CREAT` flag
  * is provided, it will create the file with the specified mode.
  *
  * @param name The path to the file to be opened. This can be an absolute or
  *             relative path.
  * @param flag Flags controlling how the file is opened. Common values include:
  *             - `O_RDONLY`: Open the file for read-only access.
  *             - `O_WRONLY`: Open the file for write-only access.
  *             - `O_RDWR`: Open the file for both reading and writing.
  *             - `O_CREAT`: Create the file if it does not exist (requires a mode argument).
  *             - `O_TRUNC`: Truncate the file to zero length if it exists.
  *             - `O_APPEND`: Open the file in append mode.
  * @param ... Optional. If the `O_CREAT` flag is specified, an additional
  *            `mode_t` argument must be provided, defining the file permissions
  *            (e.g., `0644` for user-read/write and group/world-read).
  * @return On success, returns the file descriptor.
  *         On failure, returns `errno`.
  *
  * @note The file descriptor returned can be used with other system calls like
  *       `sys_read()`, `sys_write()`, and `sys_close()`.
  *
  * @warning When using the `O_CREAT` flag, ensure to provide the `mode` argument
  *          to avoid undefined behavior. Additionally, verify that the process
  *          has the necessary permissions to access or create the file.
  *
  * @see sys_close(), sys_read(), sys_write(), open()
  */
sysret_t sys_open(const char *name, int flag, ...)
{
    int       ret   = -1;
    rt_size_t len   = 0;
    char     *kname = RT_NULL;
    mode_t    mode  = 0;

    if (!lwp_user_accessable((void *)name, 1))
    {
        return -EFAULT;
    }

    len = lwp_user_strlen(name);
    if (!len)
    {
        return -EINVAL;
    }

    kname = (char *)kmem_get(len + 1);
    if (!kname)
    {
        return -ENOMEM;
    }

    if (strncmp(kname, "/proc", 5) == 0) {
        return MAGIC_FD;
    }

    if ((flag & O_CREAT) || (flag & O_TMPFILE) == O_TMPFILE)
    {
        va_list ap;
        va_start(ap, flag);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }

    if (lwp_get_from_user(kname, (void *)name, len + 1) != (len + 1))
    {
        kmem_put(kname);
        return -EINVAL;
    }

    ret = open(kname, flag, mode);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kname);

    return ret;
}

/**
  * @brief Opens or creates a file relative to a directory file descriptor.
  *
  * This system call opens the file specified by `name`, relative to the directory
  * indicated by `dirfd`, with the specified flags and mode. It provides more
  * flexibility than `sys_open` for handling files in specific directory contexts.
  *
  * @param dirfd The file descriptor of the directory relative to which the file is opened.
  *              Special values include:
  *              - `AT_FDCWD`: Use the current working directory as the base.
  * @param name The path to the file to be opened. If `name` is absolute, `dirfd` is ignored.
  * @param flag Flags controlling how the file is opened. Common values include:
  *             - `O_RDONLY`: Open the file for read-only access.
  *             - `O_WRONLY`: Open the file for write-only access.
  *             - `O_RDWR`: Open the file for both reading and writing.
  *             - `O_CREAT`: Create the file if it does not exist.
  *             - `O_TRUNC`: Truncate the file to zero length if it exists.
  *             - `O_APPEND`: Open the file in append mode.
  *             - `O_EXCL`: Ensure the file is created exclusively (used with `O_CREAT`).
  * @param mode The permissions to set if the file is created (e.g., `0644` for user read/write
  *             and group/world read). This parameter is ignored unless `O_CREAT` is specified.
  * @return On success, returns the file descriptor.
  *         On failure, returns `errno`.
  *
  * @note The `sys_openat` system call is particularly useful for implementing secure
  *       directory traversal and operations, as it avoids race conditions when working
  *       with relative paths.
  *
  * @warning Ensure that `dirfd` is a valid directory file descriptor if a relative
  *          `name` is provided. Combining `O_CREAT` and `mode` requires proper handling
  *          to avoid unintended permission settings.
  *
  * @see sys_open(), sys_read(), sys_write(), sys_close()
  */
sysret_t sys_openat(int dirfd, const char *name, int flag, mode_t mode)
{
    int       ret   = -1;
    rt_size_t len   = 0;
    char     *kname = RT_NULL;

    len = lwp_user_strlen(name);
    if (len <= 0)
    {
        return -EINVAL;
    }

    kname = (char *)kmem_get(len + 1);
    if (!kname)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kname, (void *)name, len + 1);
    ret = openat(dirfd, kname, flag, mode);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kname);

    return ret;
}

/**
  * @brief Closes a file descriptor.
  *
  * This system call closes the file descriptor specified by `fd`, releasing any
  * resources associated with it. Once closed, the file descriptor can no longer
  * be used for operations such as reading or writing, and it may be reassigned
  * by subsequent calls to functions like `sys_open()`.
  *
  * @param fd The file descriptor to be closed. This must be a valid open file descriptor.
  * @return On success, returns 0. On failure, returns `errno`.
  *
  * @note Closing a file descriptor that is already closed results in an error.
  *       Additionally, if the file descriptor refers to a file or resource shared
  *       among multiple processes or threads, only the reference count is decremented,
  *       and the resource itself is not released until all references are closed.
  *
  * @warning Always ensure `fd` is valid before calling this function. Attempting
  *          to close an invalid or already closed descriptor may lead to undefined
  *          behavior or errors.
  *
  * @see sys_open(), sys_read(), sys_write(), close()
  */
sysret_t sys_close(int fd)
{
    int ret = close(fd);
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Performs control operations on a file descriptor.
 *
 * This system call allows a program to manipulate the behavior of a device or file
 * associated with the file descriptor `fd` by issuing a control command (`cmd`).
 * The function provides an interface to interact with device drivers, such as modifying
 * the settings of a device or performing custom operations.
 *
 * @param fd The file descriptor representing the device or file on which the ioctl
 *           command will be performed. This should be a valid, open file descriptor.
 * @param cmd The control command to be executed. The exact behavior depends on the
 *            device and the command. Commands are usually defined by the device driver
 *            or the kernel and can vary widely.
 * @param data A pointer to a buffer used for passing data to and from the command.
 *             The contents of the buffer depend on the specific command. For input
 *             commands, it may contain the data to be written to the device. For output
 *             commands, it may hold the data returned by the device.
 * @return On success, returns 0. On failure, returns `errno`.
 *
 * @note The actual functionality of `sys_ioctl` depends heavily on the specific `cmd`
 *       and the type of device associated with the file descriptor `fd`. Each device
 *       may have a different set of valid ioctl commands.
 *
 * @warning Ensure that `fd` refers to a valid file descriptor for a device that supports
 *          ioctl commands. Providing an invalid command or using an unsupported device
 *          may lead to undefined behavior or errors.
 *
 * @see sys_open(), sys_read(), sys_write(), ioctl()
 */
sysret_t sys_ioctl(int fd, unsigned long cmd, void *data)
{
    int ret = ioctl(fd, cmd, data);
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Retrieves information about a file associated with a file descriptor.
 *
 * This system call retrieves the status information about the file referred to
 * by the file descriptor `file` and stores it in the structure pointed to by `buf`.
 * It is typically used to obtain metadata such as file size, permissions, type,
 * and timestamps.
 *
 * @param file The file descriptor referring to an open file. It must be a valid file
 *             descriptor returned by `sys_open()` or similar system calls.
 * @param buf A pointer to a `struct stat` that will be populated with the file's
 *            status information, including attributes like size, access times,
 *            permissions, and more.
 * @return On success, returns `0`. On failure, returns `errno` to indicate the error.
 *
 * @note The structure `struct stat` typically includes the following fields:
 *       - `st_size`: Size of the file in bytes.
 *       - `st_mode`: File type and permissions.
 *       - `st_mtime`: Last modification time.
 *       - `st_atime`: Last access time.
 *       - `st_ctime`: Time of last status change.
 *
 * @warning Ensure that `file` is a valid, open file descriptor. Invalid file
 *          descriptors or unsupported file types may lead to errors when using
 *          this function.
 *
 * @see sys_open(), sys_close(), stat(), fstat()
 */
sysret_t sys_fstat(int file, struct stat *buf)
{
    int         ret      = -1;
    struct stat statbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct stat)))
    {
        return -EFAULT;
    }
    else
    {
        ret = fstat(file, &statbuff);

        if (ret == 0)
        {
            lwp_put_to_user(buf, &statbuff, sizeof statbuff);
        }
        else
        {
            ret = GET_ERRNO();
        }

        return ret;
    }
}

/**
 * @brief Monitors multiple file descriptors to see if they are ready for I/O.
 *
 * This system call monitors the file descriptors specified in `fds` for any
 * I/O events such as readiness for reading, writing, or exceptional conditions.
 * It waits up to the specified timeout and returns with information about which
 * file descriptors are ready for the requested operations.
 *
 * @param fds An array of `struct pollfd` structures, each specifying a file descriptor
 *            to be monitored and the events to be checked for. On return, each structure
 *            will contain the result of the poll operation for that file descriptor.
 * @param nfds The number of elements in the `fds` array.
 * @param timeout The maximum time (in milliseconds) to wait for events. If `timeout`
 *                is `-1`, the call will block indefinitely. If `timeout` is `0`,
 *                the call will return immediately.
 * @return On success, returns the number of file descriptors with events that are ready,
 *         or `0` if the timeout expired with no events. On error, returns `-1` and sets `errno`.
 *
 * @note The `pollfd` structure used for each file descriptor contains the following fields:
 *       - `fd`: The file descriptor to be monitored.
 *       - `events`: The events to monitor (e.g., `POLLIN`, `POLLOUT`).
 *       - `revents`: The events that actually occurred.
 *
 * @warning Ensure that `fds` contains valid file descriptors. Invalid descriptors or
 *          unsupported types (such as sockets) may result in errors. Also, be mindful
 *          of the timeout behavior - passing `0` will cause an immediate return, and passing
 *          `-1` will block indefinitely.
 *
 * @see sys_select(), poll(), select()
 */
sysret_t sys_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    int            ret  = -1;
    struct pollfd *kfds = RT_NULL;

    if (!lwp_user_accessable((void *)fds, nfds * sizeof *fds))
    {
        return -EFAULT;
    }

    kfds = (struct pollfd *)kmem_get(nfds * sizeof *kfds);
    if (!kfds)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kfds, fds, nfds * sizeof *kfds);

    ret = poll(kfds, nfds, timeout);
    if (ret > 0)
    {
        lwp_put_to_user(fds, kfds, nfds * sizeof *kfds);
    }

    kmem_put(kfds);
    return ret;
}

/**
 * @brief Monitors multiple file descriptors for readiness to perform I/O operations.
 *
 * This system call allows a program to monitor multiple file descriptors to see if
 * they are ready for reading, writing, or have exceptional conditions. It waits
 * for one or more of the file descriptors to become ready or for the specified
 * timeout to expire.
 *
 * @param nfds The highest-numbered file descriptor in any of the sets, plus one.
 *             This is the number of file descriptors to monitor.
 * @param readfds A pointer to an `fd_set` structure specifying the file descriptors
 *                to be checked for readability. If a file descriptor is ready to
 *                read, it will be set in the returned `fd_set`.
 * @param writefds A pointer to an `fd_set` structure specifying the file descriptors
 *                 to be checked for writability. If a file descriptor is ready to
 *                 write, it will be set in the returned `fd_set`.
 * @param exceptfds A pointer to an `fd_set` structure specifying the file descriptors
 *                  to be checked for exceptional conditions (e.g., out-of-band data).
 *                  If a file descriptor has exceptional conditions, it will be set in
 *                  the returned `fd_set`.
 * @param timeout A pointer to a `struct timeval` that specifies the maximum time
 *                to wait for an event. If `NULL`, the call blocks indefinitely. If
 *                `timeout` is `0`, the call will return immediately.
 * @return On success, returns the number of file descriptors that are ready for
 *         the requested operations, or `0` if the timeout expired without any events.
 *         On error, returns `-1` and sets `errno`.
 *
 * @note The `fd_set` structures should be initialized using the `FD_ZERO` macro
 *       and populated using the `FD_SET` macro. After the call, the `fd_set` structures
 *       will contain the file descriptors that are ready for the requested operations.
 *
 * @warning Ensure that the `fd_set` structures are properly initialized and that
 *          `nfds` correctly reflects the number of file descriptors to monitor.
 *          Passing invalid file descriptors or incorrect `nfds` can lead to undefined behavior.
 *
 * @see sys_poll(), sys_read(), sys_write(), poll(), select()
 */
sysret_t sys_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    int     ret      = -1;
    fd_set *kreadfds = RT_NULL, *kwritefds = RT_NULL, *kexceptfds = RT_NULL;

    if (readfds)
    {
        if (!lwp_user_accessable((void *)readfds, sizeof *readfds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kreadfds = (fd_set *)kmem_get(sizeof *kreadfds);
        if (!kreadfds)
        {
            SET_ERRNO(ENOMEM);
            goto quit;
        }
        lwp_get_from_user(kreadfds, readfds, sizeof *kreadfds);
    }
    if (writefds)
    {
        if (!lwp_user_accessable((void *)writefds, sizeof *writefds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kwritefds = (fd_set *)kmem_get(sizeof *kwritefds);
        if (!kwritefds)
        {
            SET_ERRNO(ENOMEM);
            goto quit;
        }
        lwp_get_from_user(kwritefds, writefds, sizeof *kwritefds);
    }
    if (exceptfds)
    {
        if (!lwp_user_accessable((void *)exceptfds, sizeof *exceptfds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kexceptfds = (fd_set *)kmem_get(sizeof *kexceptfds);
        if (!kexceptfds)
        {
            SET_ERRNO(EINVAL);
            goto quit;
        }
        lwp_get_from_user(kexceptfds, exceptfds, sizeof *kexceptfds);
    }

    ret = select(nfds, kreadfds, kwritefds, kexceptfds, timeout);
    if (kreadfds)
    {
        lwp_put_to_user(readfds, kreadfds, sizeof *kreadfds);
    }
    if (kwritefds)
    {
        lwp_put_to_user(writefds, kwritefds, sizeof *kwritefds);
    }
    if (kexceptfds)
    {
        lwp_put_to_user(exceptfds, kexceptfds, sizeof *kexceptfds);
    }
quit:
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    if (kreadfds)
    {
        kmem_put(kreadfds);
    }
    if (kwritefds)
    {
        kmem_put(kwritefds);
    }
    if (kexceptfds)
    {
        kmem_put(kexceptfds);
    }
    return ret;
}

/**
 * @brief Retrieves information about a file or directory.
 *
 * This system call obtains metadata about the specified file or directory and stores it in
 * the `buf` structure. The metadata includes attributes such as file size, permissions,
 * ownership, and timestamps.
 *
 * @param[in]  file  A pointer to the path of the file or directory to be queried.
 *                   The path should be a null-terminated string.
 * @param[out] buf   A pointer to a `struct stat` structure where the file's metadata
 *                   will be stored. This structure must be allocated by the caller.
 *
 * @return sysret_t  Returns a status code:
 *                    - `0`: The operation completed successfully, and the metadata
 *                      has been written to `buf`.
 *                    - Other error codes may indicate issues with the file path.
 *
 * @note The `file` path must be valid and accessible by the calling process. Ensure that
 *       the `buf` pointer points to a properly allocated memory region.
 *
 * @warning Passing a `NULL` pointer for `file` or `buf` may result in undefined behavior.
 *          Check all inputs before invoking this function to avoid potential issues.
 */
sysret_t sys_stat(const char *file, struct stat *buf)
{
    int         ret = 0;
    size_t      len;
    size_t      copy_len;
    char       *copy_path;
    struct stat statbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct stat)))
    {
        return -EFAULT;
    }

    len = lwp_user_strlen(file);
    if (len <= 0)
    {
        return -EFAULT;
    }

    copy_path = (char *)rt_malloc(len + 1);
    if (!copy_path)
    {
        return -ENOMEM;
    }

    copy_len = lwp_get_from_user(copy_path, (void *)file, len);
    if (copy_len == 0)
    {
        rt_free(copy_path);
        return -EFAULT;
    }
    copy_path[copy_len] = '\0';

    ret = _SYS_WRAP(stat(copy_path, &statbuff));
    rt_free(copy_path);

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statbuff, sizeof statbuff);
    }

    return ret;
}

/**
 * @brief Retrieves metadata about a file or symbolic link.
 *
 * This system call obtains metadata for the specified file or symbolic link and stores
 * it in the `buf` structure. Unlike `sys_stat`, if the specified path refers to a
 * symbolic link, this function retrieves information about the link itself, not the
 * target it points to.
 *
 * @param[in]  file  A pointer to the path of the file or symbolic link to be queried.
 *                   The path must be a null-terminated string.
 * @param[out] buf   A pointer to a `struct stat` structure where the metadata will be
 *                   stored. This structure must be allocated by the caller.
 *
 * @return sysret_t  Returns a status code:
 *                    - `0`: The operation completed successfully, and the metadata
 *                      has been written to `buf`.
 *                   - Other error codes may indicate issues with the file path.
 *
 * @note This function is particularly useful for handling symbolic links when you want
 *       to get information about the link itself rather than the target file or directory.
 *       The `file` path must be valid and accessible by the calling process.
 *
 * @warning Passing a `NULL` pointer for `file` or `buf` may result in undefined behavior.
 *          Always check inputs for validity before invoking this function.
 */
sysret_t sys_lstat(const char *file, struct stat *buf)
{
    int         ret = 0;
    size_t      len;
    size_t      copy_len;
    char       *copy_path;
    struct stat statbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct stat)))
    {
        return -EFAULT;
    }

    len = lwp_user_strlen(file);
    if (len <= 0)
    {
        return -EFAULT;
    }

    copy_path = (char *)rt_malloc(len + 1);
    if (!copy_path)
    {
        return -ENOMEM;
    }

    copy_len = lwp_get_from_user(copy_path, (void *)file, len);
    if (copy_len == 0)
    {
        rt_free(copy_path);
        return -EFAULT;
    }
    copy_path[copy_len] = '\0';
#ifdef RT_USING_DFS_V2
    ret = _SYS_WRAP(dfs_file_lstat(copy_path, &statbuff));
#else
    ret = _SYS_WRAP(stat(copy_path, &statbuff));
#endif
    rt_free(copy_path);

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statbuff, sizeof statbuff);
    }

    return ret;
}

/**
 * @brief Checks the accessibility of a file or directory.
 *
 * This function checks whether the calling process has the specified access rights for the given file or directory.
 * The check is performed based on the provided `mode`, which can indicate whether read, write, or execute permissions
 * are required.
 *
 * @param[in] filename  The path to the file or directory whose accessibility is being checked.
 * @param[in] mode      The access mode to check for. This can be a combination of the following:
 *                      - `R_OK`: Check for read permission.
 *                      - `W_OK`: Check for write permission.
 *                      - `X_OK`: Check for execute permission.
 *                      - `F_OK`: Check if the file exists.
 *
 * @return sysret_t     Returns `0` if the specified access is allowed. On failure, returns a negative error code.
 *
 * @note This function does not modify the file or directory, it only checks if the specified access rights are granted.
 *
 * @see sys_open(), sys_stat(), sys_fstat(), sys_chmod(), sys_chown()
 */
sysret_t sys_access(const char *filename, int mode)
{
    int       ret       = 0;
    rt_size_t len       = 0;
    char     *kfilename = RT_NULL;

    len = lwp_user_strlen(filename);
    if (len <= 0)
    {
        return -EINVAL;
    }

    kfilename = (char *)kmem_get(len + 1);
    if (!kfilename)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kfilename, (void *)filename, len + 1) != (len + 1))
    {
        kmem_put(kfilename);
        return -EFAULT;
    }

    ret = access(kfilename, mode);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kfilename);
    return ret;
}

/**
 * @brief Rename or move a file or directory.
 *
 * This function renames or moves a file or directory from `oldpath` to `newpath`.
 * If the `newpath` exists, it may be overwritten depending on the system's file system behavior and
 * the permissions of the files involved.
 *
 * @param[in] oldpath  The current path of the file or directory to rename or move.
 * @param[in] newpath  The new path or name to which the file or directory should be renamed or moved.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note If `oldpath` and `newpath` refer to different file systems, the behavior may vary,
 *       as the operation might involve copying and removing files instead of simply renaming them.
 *       The success of the operation also depends on the permissions of the source and destination.
 *
 * @see sys_unlink(), sys_mkdir(), sys_access()
 */
sysret_t sys_rename(const char *oldpath, const char *newpath)
{
    int ret = -1;
    int err;

    err = lwp_user_strlen(oldpath);
    if (err <= 0)
    {
        return -EFAULT;
    }

    err = lwp_user_strlen(newpath);
    if (err <= 0)
    {
        return -EFAULT;
    }
    ret = rename(oldpath, newpath);
    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Change the ownership of a file or directory.
 *
 * This function changes the owner and/or group of the file or directory specified by `pathname`.
 * The `owner` and `group` parameters represent the new owner and group IDs, respectively. If either
 * parameter is set to `-1`, that aspect (owner or group) will remain unchanged.
 *
 * @param[in] pathname  The path to the file or directory whose ownership is to be changed.
 * @param[in] owner     The new owner ID. If set to `-1`, the owner's ID is not changed.
 * @param[in] group     The new group ID. If set to `-1`, the group's ID is not changed.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note The caller must have the appropriate permissions (i.e., be the superuser or the file owner)
 *       to change the ownership of a file or directory.
 */
sysret_t sys_chown(const char *pathname, uid_t owner, gid_t group)
{
    char           *copy_file;
    size_t          len_file, copy_len_file;
    struct dfs_attr attr = {0};
    int             ret  = 0;

    len_file = lwp_user_strlen(pathname);
    if (len_file <= 0)
    {
        return -EFAULT;
    }

    copy_file = (char *)rt_malloc(len_file + 1);
    if (!copy_file)
    {
        return -ENOMEM;
    }

    copy_len_file = lwp_get_from_user(copy_file, (void *)pathname, len_file);

    if (owner >= 0)
    {
        attr.st_uid    = owner;
        attr.ia_valid |= ATTR_UID_SET;
    }

    if (group >= 0)
    {
        attr.st_gid    = group;
        attr.ia_valid |= ATTR_GID_SET;
    }

    copy_file[copy_len_file] = '\0';
    ret                      = dfs_file_setattr(copy_file, &attr);
    rt_free(copy_file);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Read data from a file descriptor at a specific offset.
 *
 * This function reads data from a file descriptor `fd` into the buffer `buf`, starting from the
 * specified byte `offset`. Unlike a regular `read` call, `sys_pread64` allows the file pointer to
 * remain unchanged after the read, as the operation directly accesses the file at the provided
 * offset.
 *
 * @param[in] fd      The file descriptor from which to read. It must be a valid open file descriptor.
 * @param[out] buf    A pointer to the buffer where the read data will be stored.
 * @param[in] size    The number of bytes to read from the file.
 * @param[in] offset  The offset in bytes from the beginning of the file to start reading from.
 *
 * @return ssize_t On success, returns the number of bytes read (which may be less than `size` if
 *                  the end of the file is reached). On error, returns a negative error code.
 *
 * @note This function is particularly useful for random access to files, allowing for efficient
 *       reads from arbitrary positions without affecting the current file pointer.
 */
ssize_t sys_pread64(int fd, void *buf, int size, size_t offset)
#ifdef RT_USING_DFS_V2
{
    ssize_t pread(int fd, void *buf, size_t len, size_t offset);
#ifdef ARCH_MM_MMU
    ssize_t ret  = -1;
    void   *kmem = RT_NULL;

    if (!size)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)buf, size))
    {
        return -EFAULT;
    }
    kmem = kmem_get(size);
    if (!kmem)
    {
        return -ENOMEM;
    }

    ret = pread(fd, kmem, size, offset);
    if (ret > 0)
    {
        lwp_put_to_user(buf, kmem, ret);
    }

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
#else
    if (!lwp_user_accessable((void *)buf, size))
    {
        return -EFAULT;
    }

    ssize_t ret = pread(fd, kmem, size, offset);
    return (ret < 0 ? GET_ERRNO() : ret);
#endif
}
#else
{
    ssize_t ret = -ENOSYS;
    return (ret < 0 ? GET_ERRNO() : ret);
}
#endif

/**
  * @brief Write data to a file descriptor at a specific offset.
  *
  * This function writes data from the buffer `buf` to the file descriptor `fd`, starting at the
  * specified byte `offset`. Unlike a regular `write` call, `sys_pwrite64` allows the file pointer to
  * remain unchanged after the write, as the operation directly writes the data to the file at the
  * provided offset.
  *
  * @param[in] fd      The file descriptor to which the data will be written. It must be a valid open
  *                    file descriptor.
  * @param[in] buf     A pointer to the buffer containing the data to be written.
  * @param[in] size    The number of bytes to write to the file.
  * @param[in] offset  The offset in bytes from the beginning of the file to start writing to.
  *
  * @return ssize_t On success, returns the number of bytes written (which may be less than `size` if
  *                  the write operation is partial). On error, returns a negative error code.
  *
  * @note This function is particularly useful for random access to files, allowing for efficient
  *       writes to arbitrary positions without affecting the current file pointer.
  */
ssize_t sys_pwrite64(int fd, void *buf, int size, size_t offset)
#ifdef RT_USING_DFS_V2
{
    ssize_t pwrite(int fd, const void *buf, size_t len, size_t offset);
    ssize_t ret  = -1;
    void   *kmem = RT_NULL;

    if (!size)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)buf, size))
    {
        return -EFAULT;
    }
    kmem = kmem_get(size);
    if (!kmem)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kmem, (void *)buf, size);

    ret = pwrite(fd, kmem, size, offset);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
}
#else
{
    ssize_t ret = -ENOSYS;
    return (ret < 0 ? GET_ERRNO() : ret);
}
#endif

sysret_t sys_fcntl(int fd, int cmd, int arg)
{
    return fcntl(fd, cmd, arg);
}

/**
 * @brief Create a new hard link to an existing file.
 *
 * This function creates a new hard link to an existing file, making the file accessible from
 * multiple filenames. The new link points to the same inode as the existing file, meaning
 * both names refer to the same underlying data. The link count for the file is incremented.
 *
 * @param[in]  existing The path to the existing file. It must be an absolute or relative path
 *                      to a file that already exists.
 * @param[in]  new      The path to the new link to be created. This can be a new filename or
 *                      an existing directory where the link will be placed.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note Hard links share the same inode number, meaning changes to the data of the file via one
 *       link will be reflected in all hard links. Deleting any of the links will not remove the
 *       file data until all links are deleted.
 */
sysret_t sys_link(const char *existing, const char *new)
{
    int ret = -1;
    int err = 0;
#ifdef RT_USING_DFS_V2
    int   len       = 0;
    char *kexisting = RT_NULL;
    char *knew      = RT_NULL;

    len = lwp_user_strlen(existing);
    if (len <= 0)
    {
        return -EFAULT;
    }

    kexisting = (char *)kmem_get(len + 1);
    if (!kexisting)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kexisting, (void *)existing, len + 1) != (len + 1))
    {
        kmem_put(kexisting);
        return -EINVAL;
    }

    len = lwp_user_strlen(new);
    if (len <= 0)
    {
        kmem_put(kexisting);
        return -EFAULT;
    }

    knew = (char *)kmem_get(len + 1);
    if (!knew)
    {
        kmem_put(kexisting);
        return -ENOMEM;
    }

    if (lwp_get_from_user(knew, (void *)new, len + 1) != (len + 1))
    {
        kmem_put(knew);
        kmem_put(kexisting);
        return -EINVAL;
    }

    ret = dfs_file_link(kexisting, knew);
    if (ret < 0)
    {
        err = GET_ERRNO();
    }

    kmem_put(knew);
    kmem_put(kexisting);

#else
    SET_ERRNO(EFAULT);
    err = GET_ERRNO();
#endif

    return (err < 0 ? err : ret);
}

/**
 * @brief Removes a file or symbolic link from the filesystem.
 *
 * This system call deletes the file or symbolic link specified by `pathname`.
 * After the call, the file will be unlinked from the filesystem, meaning it will
 * no longer be accessible via its pathname. If the file is still open, it will
 * remain available to processes that have it open until all file descriptors are
 * closed. If the file is a regular file and has no other hard links, it will be
 * removed from the disk once all references to it are closed.
 *
 * @param pathname The path to the file or symbolic link to be removed. It can be
 *                 an absolute or relative path.
 * @return On success, returns `0`. On failure, returns `errno` to indicate
 *         the error.
 *
 * @note If the file is currently being used by a process (i.e., the file descriptor
 *       is still open), it will not be immediately removed from the disk. The actual
 *       removal occurs once the file is no longer in use. Symbolic links are removed
 *       as soon as the call is executed.
 *
 * @warning Ensure that the file or link to be removed exists and that the `pathname`
 *          is correctly specified. The operation will fail if the file is open and
 *          in use by other processes or if the pathname does not exist.
 *
 * @see sys_open(), sys_remove(), unlink()
 */
sysret_t sys_unlinkat(int dirfd, const char *pathname)
{
    int       ret   = -1;
    rt_size_t len   = 0;
    char     *kname = RT_NULL;

    len = lwp_user_strlen(pathname);
    if (!len)
    {
        return -EINVAL;
    }

    kname = (char *)kmem_get(len + 1);
    if (!kname)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kname, (void *)pathname, len + 1) != (len + 1))
    {
        kmem_put(kname);
        return -EINVAL;
    }
    ret = unlink(kname);
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kname);
    return ret;
}
/**
 * @brief Create a symbolic link to an existing file or directory.
 *
 * This function creates a new symbolic link, which is a special file that contains a reference
 * to another file or directory. The symbolic link allows for easy redirection or aliasing of
 * file paths. Unlike a hard link, a symbolic link can point to a file or directory across
 * different file systems.
 *
 * @param[in]  existing The path to the existing file or directory that the symbolic link
 *                      will refer to. It must be an absolute or relative path.
 * @param[in]  new      The path to the new symbolic link to be created. This must be a valid
 *                      path where the link will be placed.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note A symbolic link is distinct from a hard link in that it points to the path of the target
 *       file or directory, rather than directly to the inode. If the target file or directory is
 *       removed or moved, the symbolic link will become "broken" and will not resolve to a valid
 *       location.
 */

sysret_t sys_symlink(const char *existing, const char *new)
{
    int ret = -1;
    int err = 0;
#ifdef ARCH_MM_MMU

    ret = lwp_user_strlen(existing);
    if (ret <= 0)
    {
        return -EFAULT;
    }

    ret = lwp_user_strlen(new);
    if (ret <= 0)
    {
        return -EFAULT;
    }
#endif
#ifdef RT_USING_DFS_V2
    ret = dfs_file_symlink(existing, new);
    if (ret < 0)
    {
        err = GET_ERRNO();
    }
#else
    SET_ERRNO(EFAULT);
#endif
    return (err < 0 ? err : ret);
}

/**
  * @brief Create an event file descriptor.
  *
  * This function creates an eventfd, which is a file descriptor used for event notification.
  * Eventfd is a simple mechanism to notify threads or processes about certain events using
  * an integer counter. It is typically used for inter-process communication (IPC) or
  * synchronization purposes, where one thread or process increments the counter to signal
  * another thread or process.
  *
  * @param[in] count  Initial value for the eventfd counter. It can be set to a non-zero
  *                   value to initialize the counter to that value.
  * @param[in] flags  Flags that control the behavior of the eventfd. Valid flags include:
  *                   - `EFD_CLOEXEC`: Set the close-on-exec flag for the eventfd.
  *                   - `EFD_NONBLOCK`: Set the non-blocking flag for the eventfd.
  *
  * @return sysret_t On success, returns a valid file descriptor referring to the eventfd. On
  *                  failure, returns a negative error code.
  *
  * @note Eventfd can be used for both counting and signaling purposes. It provides
  *       efficient signaling between threads or processes.
  */
sysret_t sys_eventfd2(unsigned int count, int flags)
{
    int ret;

    ret = eventfd(count, flags);
    return (ret < 0 ? GET_ERRNO() : ret);
}

static char *_cp_from_usr_string(char *dst, char *src, size_t length)
{
    char  *rc;
    size_t copied_bytes;
    if (length)
    {
        copied_bytes      = lwp_get_from_user(dst, src, length);
        dst[copied_bytes] = '\0';
        rc                = dst;
    }
    else
    {
        rc = RT_NULL;
    }
    return rc;
}

/**
 * @brief Mount a filesystem.
 *
 * This function mounts a filesystem onto a specified directory. It allows for mounting various
 * types of filesystems, including but not limited to `ext4`, `nfs`, and `tmpfs`. The function
 * allows the specification of the source device, the target mount point, and additional parameters
 * such as filesystem type, mount flags, and extra data.
 *
 * @param[in]  source        The source of the filesystem, which can be a device (e.g., `/dev/sda1`)
 *                           or a network resource (e.g., a NFS share). For certain filesystems like
 *                           `tmpfs`, this can be `NULL`.
 * @param[in]  target        The target directory where the filesystem will be mounted.
 *                           This should be an existing empty directory.
 * @param[in]  filesystemtype The type of filesystem to mount, e.g., `ext4`, `tmpfs`, `nfs`, etc.
 * @param[in]  mountflags    Flags that control the mount operation, such as `MS_RDONLY` for read-only
 *                           mounts or `MS_NODEV` to prevent device files from being created.
 * @param[in]  data          Optional data that is passed to the filesystem's mount handler. This
 *                           may be used for setting up specific parameters for the filesystem type.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note Mounting a filesystem on an existing mount point can replace the existing filesystem at that
 *       location. Make sure the target directory is empty before mounting to avoid any conflicts.
 */
sysret_t sys_mount(char *source, char *target, char *filesystemtype,
                   unsigned long mountflags, void *data)
{
    char       *kbuffer, *ksource, *ktarget, *kfs;
    size_t      len_source, len_target, len_fs;
    char       *tmp          = NULL;
    int         ret          = 0;
    struct stat buf          = {0};
    char       *dev_fullpath = RT_NULL;

    len_source = source ? lwp_user_strlen(source) : 0;
    if (len_source < 0)
        return -EINVAL;

    len_target = target ? lwp_user_strlen(target) : 0;
    if (len_target <= 0)
        return -EINVAL;

    len_fs = filesystemtype ? lwp_user_strlen(filesystemtype) : 0;
    if (len_fs < 0)
        return -EINVAL;

    kbuffer = (char *)rt_malloc(len_source + 1 + len_target + 1 + len_fs + 1);
    if (!kbuffer)
    {
        return -ENOMEM;
    }

    /* get parameters from user space */
    ksource = kbuffer;
    ktarget = ksource + len_source + 1;
    kfs     = ktarget + len_target + 1;
    ksource = _cp_from_usr_string(ksource, source, len_source);
    ktarget = _cp_from_usr_string(ktarget, target, len_target);
    kfs     = _cp_from_usr_string(kfs, filesystemtype, len_fs);

    if (mountflags & MS_REMOUNT)
    {
        ret = dfs_remount(ktarget, mountflags, data);
    }
    else
    {
        if (strcmp(kfs, "nfs") == 0)
        {
            tmp     = ksource;
            ksource = NULL;
        }
        if (strcmp(kfs, "tmp") == 0)
        {
            ksource = NULL;
        }

        if (ksource && !dfs_file_stat(ksource, &buf) && S_ISBLK(buf.st_mode))
        {
            dev_fullpath = dfs_normalize_path(RT_NULL, ksource);
            RT_ASSERT(rt_strncmp(dev_fullpath, "/dev/", sizeof("/dev/") - 1) == 0);
            ret = dfs_mount(dev_fullpath + sizeof("/dev/") - 1, ktarget, kfs, 0, tmp);
        }
        else
        {
            ret = dfs_mount(ksource, ktarget, kfs, 0, tmp);
        }

        if (ret < 0)
        {
            ret = -rt_get_errno();
        }
    }

    rt_free(kbuffer);
    rt_free(dev_fullpath);
    return ret;
}

/**
 * @brief Unmount a filesystem.
 *
 * This function unmounts a previously mounted filesystem from a specified target directory or file.
 * It removes the filesystem from the system, making the resources associated with it available for
 * other uses. It can also support additional flags to control the unmounting behavior.
 *
 * @param[in]  __special_file The target directory or mount point from which the filesystem is to be
 *                            unmounted. This should be a valid mount point that was previously mounted.
 * @param[in]  __flags        Flags that control the unmounting behavior. Common flags include:
 *                            - `MNT_FORCE`: Forces the unmount even if the filesystem is busy.
 *                            - `MNT_DETACH`: Detaches the filesystem, allowing it to be unmounted
 *                              asynchronously.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note The `MNT_FORCE` flag should be used with caution, as it may result in data loss or corruption
 *       if there are pending writes or active processes using the filesystem.
 *
 * @see sys_mount
 */
sysret_t sys_umount2(char *__special_file, int __flags)
{
    char  *copy_special_file;
    size_t len_special_file, copy_len_special_file;
    int    ret = 0;

    len_special_file = lwp_user_strlen(__special_file);
    if (len_special_file <= 0)
    {
        return -EFAULT;
    }

    copy_special_file = (char *)rt_malloc(len_special_file + 1);
    if (!copy_special_file)
    {
        return -ENOMEM;
    }

    copy_len_special_file                    = lwp_get_from_user(copy_special_file, __special_file, len_special_file);
    copy_special_file[copy_len_special_file] = '\0';

    ret = dfs_unmount(copy_special_file);
    rt_free(copy_special_file);

    return ret;
}

/**
 * @brief Gets the current working directory.
 *
 * This function retrieves the absolute pathname of the current working directory
 * and stores it in the provided buffer. The buffer must be large enough to hold
 * the directory path, including the null-terminator. If the buffer is too small,
 * the function will return an error.
 *
 * @param[out] buf     A pointer to a buffer where the current working directory
 *                     path will be stored. The buffer should be large enough
 *                     to hold the path, including the null-terminator.
 * @param[in] size     The size of the buffer in bytes. The buffer must be large enough
 *                     to accommodate the full path.
 *
 * @return long        On success, returns the number of bytes written to the buffer
 *                     (not including the null-terminator). If the buffer is not large
 *                     enough, returns a negative error code.
 *
 * @note The maximum path length depends on the system's configuration.
 *       Ensure the buffer size is sufficient to hold the entire path.
 *
 * @see sys_chdir(), sys_getcwd_r(), sys_realpath()
 */
sysret_t sys_getcwd(char *buf, size_t size)
{
    char *tmp = RT_NULL;
    long  ret = -1;

    if (!lwp_user_accessable((void *)buf, size))
    {
        return ret;
    }

    tmp = (char *)rt_malloc(size);
    if (!tmp)
    {
        return ret;
    }

    if (getcwd(tmp, size) != RT_NULL)
    {
        if (lwp_put_to_user(buf, tmp, size) > 0)
        {
            if (buf != RT_NULL)
                ret = strlen(buf);
            else
                ret = -EFAULT;
        }
    }

    rt_free(tmp);

    return ret;
}

/**
  * @brief Changes the current working directory.
  *
  * This function changes the current working directory of the calling process
  * to the directory specified by the given path. The path can be absolute or
  * relative. If the specified path does not exist or the process does not have
  * sufficient permissions, the function will return an error.
  *
  * @param[in] path     The path to the new working directory. This can be either
  *                     an absolute or a relative path.
  *
  * @return sysret_t    Returns `0` on success, indicating that the working
  *                     directory was successfully changed. On failure, returns a
  *                     negative error code indicating the reason for failure.
  *
  * @note If the specified path is a relative path, it is interpreted relative
  *       to the current working directory.
  *
  * @see sys_getcwd(), sys_chdir() for changing directories, sys_opendir(), sys_stat()
  */
sysret_t sys_chdir(const char *path)
{
    int   err = 0;
    int   len = 0;
    int   errcode;
    char *kpath = RT_NULL;

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    kpath = (char *)kmem_get(len + 1);
    if (!kpath)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kpath, (void *)path, len + 1) != (len + 1))
    {
        kmem_put(kpath);
        return -EINVAL;
    }

    err     = chdir(kpath);
    errcode = err != 0 ? GET_ERRNO() : 0;

    kmem_put(kpath);

    return errcode;
}

/**
  * @brief Changes the current working directory to the one associated with the specified file descriptor.
  *
  * This function changes the current working directory of the calling process
  * to the directory associated with the file descriptor `fd`. The file descriptor
  * should refer to an open directory. If the file descriptor does not refer to a
  * directory, or if the process lacks the necessary permissions, the function will
  * return an error.
  *
  * @param[in] fd   The file descriptor referring to the directory to which the current
  *                 working directory should be changed.
  *
  * @return sysret_t    Returns `0` on success, indicating the current working directory
  *                     was successfully changed. On failure, returns a negative error code.
  *
  * @note The file descriptor must refer to a directory. If it refers to a file or other
  *       non-directory object, the operation will fail.
  *
  * @see sys_chdir(), sys_getcwd(), sys_opendir(), sys_open()
  */
sysret_t sys_fchdir(int fd)
{
    int errcode = -ENOSYS;
#ifdef RT_USING_DFS_V2
    int              err = -1;
    struct dfs_file *d;
    char            *kpath;

    d = fd_get(fd);
    if (!d || !d->vnode)
    {
        return -EBADF;
    }
    kpath = dfs_dentry_full_path(d->dentry);
    if (!kpath)
    {
        return -EACCES;
    }

    err     = chdir(kpath);
    errcode = err != 0 ? GET_ERRNO() : 0;

    kmem_put(kpath);
#endif
    return errcode;
}

/**
  * @brief Creates a new directory with the specified path and mode.
  *
  * This function creates a new directory with the specified path and mode.
  * The directory is created with the permissions specified by the `mode` parameter.
  * If the directory already exists, the function will return an error.
  *
  * @param[in] path     The path of the directory to be created. This can be an absolute
  *                     or relative path. If the directory does not exist, it will be created.
  * @param[in] mode     The permissions to be set for the new directory. This parameter
  *                     specifies the access permissions for the directory owner, group, and others.
  *
  * @return sysret_t    Returns `0` on success, indicating that the directory was successfully
  *                     created. On failure, returns a negative error code indicating the reason for failure.
  *
  * @note The `mode` parameter specifies the permissions for the new directory. The permissions
  *       are typically specified using the `S_IRWXU`, `S_IRWXG`, and `S_IRWXO` macros, which
  *       define the read, write, and execute permissions for the owner, group, and others.
  *
  * @see sys_rmdir(), sys_chdir(), sys_mkdirat()
  */
sysret_t sys_mkdir(int dirfd, const char *path, mode_t mode)
{
    int   err   = 0;
    int   len   = 0;
    char *kpath = RT_NULL;

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    kpath = (char *)kmem_get(len + 1);
    if (!kpath)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kpath, (void *)path, len + 1) != (len + 1))
    {
        kmem_put(kpath);
        return -EINVAL;
    }

    err = _SYS_WRAP(mkdir(kpath, mode));

    kmem_put(kpath);

    return err;
}

/**
  * @brief Removes the specified directory.
  *
  * This function removes the directory specified by the given path. The directory
  * must be empty for the operation to succeed. If the directory is not empty, the
  * function will return an error. If the directory does not exist or the process
  * lacks the necessary permissions, the function will also return an error.
  *
  * @param[in] path     The path of the directory to be removed. This can be an absolute
  *                     or relative path. The directory must be empty for the operation to succeed.
  *
  * @return sysret_t    Returns `0` on success, indicating that the directory was successfully
  *                     removed. On failure, returns a negative error code indicating the reason for failure.
  *
  * @note The directory must be empty for the operation to succeed. If the directory contains
  *       files or subdirectories, the operation will fail. To remove a non-empty directory,
  *       the contents must be deleted first.
  *
  * @see sys_mkdir(), sys_chdir(), sys_rmdirat()
  */
sysret_t sys_rmdir(const char *path)
{
    int   err   = 0;
    int   ret   = 0;
    int   len   = 0;
    char *kpath = RT_NULL;

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    kpath = (char *)kmem_get(len + 1);
    if (!kpath)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kpath, (void *)path, len + 1) != (len + 1))
    {
        kmem_put(kpath);
        return -EINVAL;
    }

    ret = rmdir(kpath);
    if (ret < 0)
    {
        err = GET_ERRNO();
    }

    kmem_put(kpath);

    return (err < 0 ? err : ret);
}

/**
  * @brief Reads directory entries.
  *
  * This function reads the directory entries from the directory stream specified by the file descriptor `fd`.
  * It stores the directory entries in the buffer pointed to by `dirp`, up to the specified number of bytes (`nbytes`).
  * The entries are returned in a format compatible with the `struct libc_dirent` structure.
  *
  * @param[in] fd      The file descriptor referring to an open directory. This descriptor must be obtained
  *                    from a call to `sys_open()` with the appropriate flags for directory reading.
  * @param[out] dirp   A pointer to a buffer where the directory entries will be stored.
  *                    The buffer must be large enough to hold at least `nbytes` bytes of directory entries.
  * @param[in] nbytes  The size of the buffer (`dirp`) in bytes. It limits the number of directory entries
  *                    that can be read in a single call. The function will return as many entries as possible
  *                    that fit within the buffer size.
  *
  * @return sysret_t   Returns the number of bytes read on success, which may be less than `nbytes` if there
  *                     are fewer entries in the directory or if the buffer is too small.
  *                     On failure, returns a negative error code.
  *
  * @note If the function returns 0, it indicates the end of the directory stream. A negative return value
  *       indicates an error. The caller can use the returned number of bytes to process the entries in `dirp`.
  *
  * @see sys_open(), sys_close(), sys_readdir(), sys_stat()
  */
sysret_t sys_getdents(int fd, struct libc_dirent *dirp, size_t nbytes)
{
    int              ret = -1;
    struct dfs_file *file;
    size_t           cnt        = (nbytes / sizeof(struct libc_dirent));
    size_t           rtt_nbytes = 0;
    struct dirent   *rtt_dirp;

    if (!lwp_user_accessable((void *)dirp, sizeof(struct libc_dirent)))
    {
        return -EFAULT;
    }

    if (cnt == 0)
    {
        return -EINVAL;
    }
    rtt_nbytes = cnt * sizeof(struct dirent);
    rtt_dirp   = (struct dirent *)rt_malloc(rtt_nbytes);
    if (!rtt_dirp)
    {
        return -ENOMEM;
    }
    file = fd_get(fd);
    ret  = dfs_file_getdents(file, rtt_dirp, rtt_nbytes);
    if (ret > 0)
    {
        size_t i = 0;
        cnt      = ret / sizeof(struct dirent);
        for (i = 0; i < cnt; i++)
        {
            dirp[i].d_ino    = 0;
            dirp[i].d_off    = i * sizeof(struct libc_dirent);
            dirp[i].d_type   = rtt_dirp[i].d_type;
            dirp[i].d_reclen = sizeof(struct libc_dirent);
            strcpy(dirp[i].d_name, rtt_dirp[i].d_name);
        }
        ret = cnt * sizeof(struct libc_dirent);
    }

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    rt_free(rtt_dirp);

    return ret;
}

/**
 * @brief Change file permissions.
 *
 * This function changes the permissions of a file or directory specified by the `pathname`.
 * The new permissions are specified using the `mode` argument, which is a bitwise OR of permission bits.
 * The permissions apply to the file owner, group, and others, depending on the value of `mode`.
 *
 * @param[in] pathname  The path to the file or directory whose permissions are to be changed.
 * @param[in] mode      The new permissions to set, represented as a bitwise OR of permission flags.
 *                      For example, `S_IRUSR`, `S_IWUSR`, `S_IRGRP`, etc.
 *
 * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
 *
 * @note If the file or directory is a symbolic link, this function will modify the permissions of the symbolic link itself,
 *       not the target file or directory.
 */
sysret_t sys_chmod(const char *pathname, mode_t mode)
{
    char           *copy_file;
    size_t          len_file, copy_len_file;
    struct dfs_attr attr = {0};
    int             ret  = 0;

    len_file = lwp_user_strlen(pathname);
    if (len_file <= 0)
    {
        return -EFAULT;
    }

    copy_file = (char *)rt_malloc(len_file + 1);
    if (!copy_file)
    {
        return -ENOMEM;
    }

    copy_len_file = lwp_get_from_user(copy_file, (void *)pathname, len_file);

    attr.st_mode   = mode;
    attr.ia_valid |= ATTR_MODE_SET;

    copy_file[copy_len_file] = '\0';
    ret                      = dfs_file_setattr(copy_file, &attr);
    rt_free(copy_file);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Flush the file descriptors' data to disk.
 *
 * This function flushes all modified data of the file associated with the specified
 * file descriptor to disk, ensuring that any changes made to the file are committed
 * to permanent storage.
 *
 * @param[in] fd The file descriptor associated with the file to be flushed. It should
 *               refer to an open file.
 *
 * @return sysret_t Returns `0` (0) on success. On failure, returns a negative
 *                  error code.
 *
 * @note The `fsync` function ensures that all data written to the file is physically
 *       stored on disk, but it does not guarantee that all file metadata is flushed.
 *       To flush both data and metadata, `fdatasync` can be used.
 */
sysret_t sys_fsync(int fd)
{
    int res = fsync(fd);
    if (res < 0)
        res = rt_get_errno();
    return res;
}

/**
 * @brief Read the value of a symbolic link.
 *
 * This function reads the value of a symbolic link and stores it in the provided buffer. The value is the
 * path to which the symbolic link points. If the symbolic link is too long to fit in the provided buffer,
 * the function returns the number of bytes needed to store the entire path (not including the terminating null byte).
 *
 * @param[in]  path   The path of the symbolic link to read.
 * @param[out] buf    A buffer where the symbolic link's target will be stored. The buffer must be large enough
 *                    to hold the path of the symbolic link.
 * @param[in]  bufsz  The size of the buffer `buf`. It specifies the maximum number of bytes to read.
 *
 * @return ssize_t The number of bytes written to `buf` (excluding the terminating null byte) on success.
 *                 On failure, it returns a negative error code:
 *                 - `-EINVAL`: Invalid path.
 *                 - `-ENOMEM`: Insufficient memory to read the link.
 *                 - `-EFAULT`: Invalid address for the `buf`.
 *
 * @note It will (silently) truncate the contents(to a length of bufsiz characters),
 *       in case the buffer is too small to hold all of the contents.
 *
 * @see sys_symlink(), sys_lstat()
 */
ssize_t sys_readlink(char *path, char *buf, size_t bufsz)
{
    size_t len, copy_len;
    int    err, rtn;
    char  *copy_path;

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    if (!lwp_user_accessable(buf, bufsz))
    {
        return -EINVAL;
    }

    copy_path = (char *)rt_malloc(len + 1);
    if (!copy_path)
    {
        return -ENOMEM;
    }

    copy_len            = lwp_get_from_user(copy_path, path, len);
    copy_path[copy_len] = '\0';

    char *link_fn = (char *)rt_malloc(DFS_PATH_MAX);
    if (link_fn)
    {
        err = dfs_file_readlink(copy_path, link_fn, DFS_PATH_MAX);
        if (err > 0)
        {
            buf[bufsz > err ? err : bufsz] = '\0';
            rtn                            = lwp_put_to_user(buf, link_fn, bufsz > err ? err : bufsz);
        }
        else
        {
            rtn = -EIO;
        }
        rt_free(link_fn);
    }
    else
    {
        rtn = -ENOMEM;
    }

    rt_free(copy_path);
    return rtn;
}

/**
 * @brief Get filesystem statistics.
 *
 * This function retrieves statistics about the filesystem at the specified path,
 * storing the results in the provided `statfs` structure. It can be used to obtain
 * information such as the total number of blocks, free blocks, available inodes, etc.
 *
 * @param[in]  path  The path to the filesystem to query. If the path is the root directory
 *                   (`"/"`), it returns statistics for the root filesystem.
 * @param[out] buf   A pointer to a `statfs` structure where the filesystem statistics will
 *                   be stored. This structure includes information such as:
 *                   - `f_type`: The type of the filesystem.
 *                   - `f_bsize`: The optimal block size for I/O operations.
 *                   - `f_blocks`: Total number of blocks in the filesystem.
 *                   - `f_bfree`: Number of free blocks.
 *                   - `f_bavail`: Number of free blocks available to non-superuser.
 *                   - `f_files`: Total number of file nodes (inodes).
 *                   - `f_ffree`: Number of free inodes.
 *                   - `f_favail`: Number of inodes available to non-superuser.
 *                   - `f_flag`: Flags describing the filesystem.
 *                   - `f_namelen`: Maximum length of a filename.
 *
 * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
 *
 * @note This function is useful for determining the available space and file system
 *       characteristics of a mounted filesystem.
 *
 * @see sys_fstatfs
 */
sysret_t sys_statfs(const char *path, struct statfs *buf)
{
    int           ret = 0;
    size_t        len;
    size_t        copy_len;
    char         *copy_path;
    struct statfs statfsbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct statfs)))
    {
        return -EFAULT;
    }

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    copy_path = (char *)rt_malloc(len + 1);
    if (!copy_path)
    {
        return -ENOMEM;
    }

    copy_len = lwp_get_from_user(copy_path, (void *)path, len);
    if (copy_len == 0)
    {
        rt_free(copy_path);
        return -EFAULT;
    }
    copy_path[copy_len] = '\0';

    ret = _SYS_WRAP(statfs(copy_path, &statfsbuff));
    rt_free(copy_path);

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statfsbuff, sizeof statfsbuff);
    }

    return ret;
}

/**
  * @brief Get extended filesystem statistics (64-bit).
  *
  * This function retrieves extended statistics about the filesystem at the specified path,
  * using 64-bit values for larger filesystems or filesystems with a large number of blocks or inodes.
  * The information is stored in the provided `statfs` structure, which includes details such as total
  * blocks, free blocks, available inodes, etc.
  *
  * @param[in]  path  The path to the filesystem to query. Typically, this would be the root directory
  *                   (`"/"`) for the root filesystem, or any other directory on the filesystem.
  * @param[in]  sz    The size of the `statfs` structure. This parameter allows for future extensions
  *                   of the `statfs` structure without breaking compatibility with older applications.
  * @param[out] buf   A pointer to a `statfs` structure where the extended filesystem statistics
  *                   will be stored. This structure includes information such as:
  *                   - `f_bsize`: The optimal block size for I/O operations.
  *                   - `f_blocks`: Total number of blocks in the filesystem.
  *                   - `f_bfree`: Number of free blocks.
  *                   - `f_bavail`: Number of free blocks available to non-superuser.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note This function is particularly useful for querying large filesystems or filesystems with
  *       64-bit addresses or data values, and is an extended version of the standard `sys_statfs`.
  *
  * @see sys_statfs
  */
sysret_t sys_statfs64(const char *path, size_t sz, struct statfs *buf)
{
    int           ret = 0;
    size_t        len;
    size_t        copy_len;
    char         *copy_path;
    struct statfs statfsbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct statfs)))
    {
        return -EFAULT;
    }

    if (sz != sizeof(struct statfs))
    {
        return -EINVAL;
    }

    len = lwp_user_strlen(path);
    if (len <= 0)
    {
        return -EFAULT;
    }

    copy_path = (char *)rt_malloc(len + 1);
    if (!copy_path)
    {
        return -ENOMEM;
    }

    copy_len = lwp_get_from_user(copy_path, (void *)path, len);
    if (copy_len == 0)
    {
        rt_free(copy_path);
        return -EFAULT;
    }
    copy_path[copy_len] = '\0';

    ret = _SYS_WRAP(statfs(copy_path, &statfsbuff));
    rt_free(copy_path);

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statfsbuff, sizeof statfsbuff);
    }

    return ret;
}

/**
  * @brief Get filesystem statistics for a file descriptor.
  *
  * This function retrieves statistics about the filesystem containing the file referred to by the
  * file descriptor `fd`. The information is stored in the provided `statfs` structure, which includes
  * details such as total blocks, free blocks, available inodes, etc.
  *
  * @param[in]  fd    The file descriptor referring to an open file. The file descriptor must be
  *                   valid and represent a file on a mounted filesystem.
  * @param[out] buf   A pointer to a `statfs` structure where the filesystem statistics will be
  *                   stored. This structure includes information such as:
  *                   - `f_bsize`: The optimal block size for I/O operations.
  *                   - `f_blocks`: Total number of blocks in the filesystem.
  *                   - `f_bfree`: Number of free blocks.
  *                   - `f_bavail`: Number of free blocks available to non-superuser.
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  *
  * @note This function is useful for obtaining filesystem information about a specific file
  *       represented by its file descriptor, rather than querying the filesystem associated with
  *       a specific path.
  *
  * @see sys_statfs
  */
sysret_t sys_fstatfs(int fd, struct statfs *buf)
{
    int           ret        = 0;
    struct statfs statfsbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct statfs)))
    {
        return -EFAULT;
    }

    ret = _SYS_WRAP(fstatfs(fd, &statfsbuff));

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statfsbuff, sizeof statfsbuff);
    }

    return ret;
}

/**
  * @brief Get 64-bit filesystem statistics for a file descriptor.
  *
  * This function retrieves 64-bit statistics about the filesystem containing the file referred to by
  * the file descriptor `fd`. The statistics are stored in the provided `statfs` structure, which
  * includes details such as total blocks, free blocks, available inodes, etc. The function differs
  * from `sys_fstatfs` in that it supports 64-bit values for filesystem sizes and counts.
  *
  * @param[in]  fd    The file descriptor referring to an open file. The file descriptor must be
  *                   valid and represent a file on a mounted filesystem.
  * @param[in]  sz    The size of the `statfs` structure (typically used to ensure compatibility with
  *                   different versions of the structure).
  * @param[out] buf   A pointer to a `statfs` structure where the filesystem statistics will be
  *                   stored. This structure includes information such as:
  *                   - `f_bsize`: The optimal block size for I/O operations.
  *                   - `f_blocks`: Total number of blocks in the filesystem (64-bit).
  *                   - `f_bfree`: Number of free blocks (64-bit).
  *                   - `f_bavail`: Number of free blocks available to non-superuser (64-bit).
  *
  * @return sysret_t Returns `0` on success. On failure, returns a negative error code.
  * @note This function is particularly useful for systems supporting 64-bit filesystem statistics.
  *       It provides extended accuracy for large filesystems, including those with very large
  *       numbers of blocks or inodes.
  *
  * @see sys_fstatfs
  */
sysret_t sys_fstatfs64(int fd, size_t sz, struct statfs *buf)
{
    int           ret        = 0;
    struct statfs statfsbuff = {0};

    if (!lwp_user_accessable((void *)buf, sizeof(struct statfs)))
    {
        return -EFAULT;
    }

    if (sz != sizeof(struct statfs))
    {
        return -EINVAL;
    }

    ret = _SYS_WRAP(fstatfs(fd, &statfsbuff));

    if (ret == 0)
    {
        lwp_put_to_user(buf, &statfsbuff, sizeof statfsbuff);
    }

    return ret;
}

/**
  * @brief Create an epoll instance.
  *
  * This function creates an epoll instance, which is used for monitoring multiple file descriptors
  * to see if I/O is possible on them. It allows a program to efficiently wait for events such as
  * data being available for reading or space becoming available for writing. Epoll provides a scalable
  * mechanism for managing large numbers of file descriptors.
  *
  * @param[in] flags  Flags that control the behavior of the epoll instance. The valid flags include:
  *                   - `EPOLL_CLOEXEC`: Set the close-on-exec flag for the epoll instance.
  *                   - `EPOLL_NONBLOCK`: Set the non-blocking flag for the epoll instance.
  *
  * @return sysret_t On success, returns a file descriptor for the epoll instance. On failure,
  *                  returns a negative error code.
  *
  * @note The `sys_epoll_create1` function is similar to `sys_epoll_create`, but it allows for
  *       additional control over the epoll instance creation via flags.
  */
sysret_t sys_epoll_create1(int flags)
{
    int ret;

    ret = epoll_create(flags);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Control an epoll instance.
  *
  * This function performs control operations on an epoll instance, such as adding, modifying,
  * or removing file descriptors from the epoll instance's interest list.
  *
  * @param[in] fd    The file descriptor of the epoll instance created using `sys_epoll_create` or `sys_epoll_create1`.
  * @param[in] op    The operation to perform on the epoll instance. It can be one of the following:
  *                  - `EPOLL_CTL_ADD`: Add the specified file descriptor to the epoll interest list.
  *                  - `EPOLL_CTL_MOD`: Modify the event mask of an existing file descriptor in the epoll interest list.
  *                  - `EPOLL_CTL_DEL`: Remove the specified file descriptor from the epoll interest list.
  * @param[in] fd2   The file descriptor to be added, modified, or removed from the epoll interest list.
  * @param[in] ev    A pointer to an `epoll_event` structure that describes the event to be associated with `fd2`.
  *                  This parameter is required for `EPOLL_CTL_ADD` and `EPOLL_CTL_MOD`, but not for `EPOLL_CTL_DEL`.
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note This function is typically used to manage the set of file descriptors monitored by an epoll instance.
  */
sysret_t sys_epoll_ctl(int fd, int op, int fd2, struct epoll_event *ev)
{
    int                 ret = 0;
    struct epoll_event *kev = RT_NULL;

    if (ev)
    {
        if (!lwp_user_accessable((void *)ev, sizeof(struct epoll_event)))
            return -EFAULT;

        kev = kmem_get(sizeof(struct epoll_event));
        if (kev == RT_NULL)
        {
            return -ENOMEM;
        }

        if (lwp_get_from_user(kev, ev, sizeof(struct epoll_event)) != sizeof(struct epoll_event))
        {
            kmem_put(kev);
            return -EINVAL;
        }

        ret = epoll_ctl(fd, op, fd2, kev);

        kmem_put(kev);
    }
    else
    {
        ret = epoll_ctl(fd, op, fd2, RT_NULL);
    }

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Wait for events on an epoll file descriptor, with the ability to block for specific signals.
  *
  * This function waits for events on an epoll file descriptor. It blocks until one or more events
  * are available or a timeout occurs. In addition to waiting for events, it can also block for specific signals
  * as specified by the `sigs` argument.
  *
  * @param[in] fd          The file descriptor of the epoll instance, created using `sys_epoll_create` or `sys_epoll_create1`.
  * @param[out] ev         A pointer to an array of `epoll_event` structures that will receive the events that have occurred.
  * @param[in] cnt         The maximum number of events to return. This specifies the size of the `ev` array.
  * @param[in] to          The timeout in milliseconds. A negative value means no timeout, and `0` means non-blocking.
  * @param[in] sigs        A pointer to a signal set (`sigset_t`) that specifies the signals to block during the wait.
  *                        If `NULL`, no signals are blocked.
  * @param[in] sigsetsize  The size of the signal set (`sigs`) in bytes. This should be the size of `sigset_t` if `sigs` is not `NULL`.
  *
  * @return sysret_t On success, returns the number of events returned (may be `0` if the timeout expires with no events).
  *                  On failure, returns a negative error code.
  *
  * @note This function is similar to `sys_epoll_wait`, but it also allows for signal handling, blocking the calling thread
  *       from receiving signals specified in the `sigs` set while waiting for events.
  */
sysret_t sys_epoll_pwait(int                 fd,
                         struct epoll_event *ev,
                         int                 cnt,
                         int                 to,
                         const sigset_t     *sigs,
                         unsigned long       sigsetsize)
{
    int                 ret   = 0;
    struct epoll_event *kev   = RT_NULL;
    sigset_t           *ksigs = RT_NULL;

    if (!lwp_user_accessable((void *)ev, cnt * sizeof(struct epoll_event)))
        return -EFAULT;

    kev = kmem_get(cnt * sizeof(struct epoll_event));
    if (kev == RT_NULL)
    {
        return -ENOMEM;
    }

    if (sigs != RT_NULL)
    {
        if (!lwp_user_accessable((void *)sigs, sizeof(sigset_t)))
        {
            kmem_put(kev);
            return -EFAULT;
        }

        ksigs = kmem_get(sizeof(sigset_t));
        if (ksigs == RT_NULL)
        {
            kmem_put(kev);
            return -ENOMEM;
        }

        if (lwp_get_from_user(ksigs, (void *)sigs, sizeof(sigset_t)) != sizeof(sigset_t))
        {
            kmem_put(kev);
            kmem_put(ksigs);
            return -EINVAL;
        }
    }

    ret = epoll_pwait(fd, kev, cnt, to, ksigs);

    if (ret > 0)
    {
        lwp_put_to_user((void *)ev, kev, ret * sizeof(struct epoll_event));
    }

    if (sigs != RT_NULL)
        kmem_put(ksigs);

    kmem_put(kev);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Truncate a file to a specified length.
  *
  * This function resizes the file associated with the given file descriptor `fd` to the specified length.
  * If the current size of the file is greater than the specified length, the file is truncated. If the file is smaller,
  * it is extended, and the new space is initialized to zero.
  *
  * @param[in] fd       The file descriptor referring to the file to truncate. This must be a valid open file descriptor.
  * @param[in] length   The new length of the file. The file will be truncated or extended to this size.
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note The file descriptor `fd` must be opened with write permissions for this operation to succeed.
  */
sysret_t sys_ftruncate(int fd, size_t length)
{
    int ret;

    ret = ftruncate(fd, length);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
  * @brief Set file access and modification times.
  *
  * This function updates the access and modification times of a file or directory referenced by `__fd` or `__path`.
  * If `__fd` is a valid file descriptor, the times will be applied to the file or directory it refers to.
  * If `__fd` is `AT_FDCWD`, the times will be applied to the file or directory specified by `__path`.
  * The `__times` argument consists of two `timespec` values: the first represents the access time,
  * and the second represents the modification time. If `__times` is `NULL`, the current time is used.
  *
  * @param[in] __fd       The file descriptor of the file or directory to modify, or `AT_FDCWD` to modify using `__path`.
  * @param[in] __path     The path to the file or directory to modify. Ignored if `__fd` is not `AT_FDCWD`.
  * @param[in] __times    An array of two `timespec` structures. The first element is the access time, and the second is the modification time.
  *                       If `__times` is `NULL`, the current time is used for both access and modification times.
  * @param[in] __flags    Flags to modify behavior. Supported flags include:
  *                       - `AT_SYMLINK_NOFOLLOW`: Do not follow symbolic links.
  *                       - `AT_NO_AUTOMOUNT`: Do not trigger automounting.
  *
  * @return sysret_t On success, returns `0`. On failure, returns a negative error code.
  *
  * @note This function modifies both access and modification times of files, and may affect file system timestamps.
  */
sysret_t sys_utimensat(int __fd, const char *__path, const struct timespec __times[2], int __flags)
{
#ifdef RT_USING_DFS_V2
    int       ret   = -1;
    rt_size_t len   = 0;
    char     *kpath = RT_NULL;

    len = lwp_user_strlen(__path);
    if (len <= 0)
    {
        return -EINVAL;
    }

    kpath = (char *)kmem_get(len + 1);
    if (!kpath)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kpath, (void *)__path, len + 1);
    ret = utimensat(__fd, kpath, __times, __flags);

    kmem_put(kpath);

    return ret;
#else
    return -1;
#endif
}

sysret_t sys_sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    if (offset != RT_NULL) {
        if (!lwp_user_accessable(offset, sizeof(off_t))) {
            return -EFAULT;
        }

        off_t readoffset;
        lwp_get_from_user(&readoffset, offset, sizeof(off_t));
        lseek(in_fd, readoffset, SEEK_SET);
    }

    void *buffer = rt_malloc(count);
    if (buffer == RT_NULL) {
        return -ENOMEM;
    }

    ssize_t c = read(in_fd, buffer, count);
    if (c < 0) {
        rt_free(buffer);
        return c;
    }
    
    c = write(out_fd, buffer, c);

    if (offset != RT_NULL) {
        off_t readoffset;
        readoffset = lseek(in_fd, 0, SEEK_CUR);
        lwp_put_to_user(offset, &readoffset, sizeof(off_t));
    }

    rt_free(buffer);

    return c;
}

sysret_t sys_fstatat(int dirfd, const char *pathname, struct stat *buf, int flags)
{
    int         ret       = -1;
    rt_size_t   len       = 0;
    char       *kpathname = RT_NULL;
    struct stat statbuff  = {0};
    int         fd        = -1;

    // 检查用户空间的buf指针是否可访问
    if (!lwp_user_accessable((void *)buf, sizeof(struct stat)))
    {
        return -EFAULT;
    }

    // 获取pathname的长度并检查有效性
    len = lwp_user_strlen(pathname);
    if (len <= 0)
    {
        return -EFAULT;
    }

    // 分配内核内存并拷贝pathname
    kpathname = (char *)kmem_get(len + 1);
    if (!kpathname)
    {
        return -ENOMEM;
    }

    // 从用户空间拷贝pathname到内核空间
    if (lwp_get_from_user(kpathname, (void *)pathname, len + 1) != (len + 1))
    {
        kmem_put(kpathname);
        return -EINVAL;
    }

    // 临时打开文件以获取其状态
    int open_flags = O_RDONLY;
    if (flags & AT_SYMLINK_NOFOLLOW)
    {
        open_flags |= O_NOFOLLOW;
    }
    
    fd = openat(dirfd, kpathname, open_flags);
    if (fd < 0)
    {
        kmem_put(kpathname);
        return GET_ERRNO();
    }

    // 获取文件状态
    ret = fstat(fd, &statbuff);
    
    // 关闭临时打开的文件
    close(fd);
    kmem_put(kpathname);

    // 如果成功获取状态，将结果拷贝到用户空间
    if (ret == 0)
    {
        lwp_put_to_user(buf, &statbuff, sizeof statbuff);
    }
    else
    {
        ret = GET_ERRNO();
    }

    return ret;
}

sysret_t sys_fsnyc(int fd)
{
    int ret;

    ret = fsync(fd);

    return (ret < 0 ? GET_ERRNO() : ret);
}

sysret_t sys_sync()
{
    return 0;
}

sysret_t sys_pselect6(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
                     const struct timespec *timeout_ts, const sigset_t *sigmask)
{
    int     ret      = -1;
    fd_set *kreadfds = RT_NULL, *kwritefds = RT_NULL, *kexceptfds = RT_NULL;
    struct timeval timeout;
    struct timeval *ptimeout = RT_NULL;
    sigset_t *ksigmask = RT_NULL;
    sigset_t old_sigmask;

    // 检查并复制readfds
    if (readfds)
    {
        if (!lwp_user_accessable((void *)readfds, sizeof *readfds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kreadfds = (fd_set *)kmem_get(sizeof *kreadfds);
        if (!kreadfds)
        {
            SET_ERRNO(ENOMEM);
            goto quit;
        }
        lwp_get_from_user(kreadfds, readfds, sizeof *kreadfds);
    }
    
    // 检查并复制writefds
    if (writefds)
    {
        if (!lwp_user_accessable((void *)writefds, sizeof *writefds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kwritefds = (fd_set *)kmem_get(sizeof *kwritefds);
        if (!kwritefds)
        {
            SET_ERRNO(ENOMEM);
            goto quit;
        }
        lwp_get_from_user(kwritefds, writefds, sizeof *kwritefds);
    }
    
    // 检查并复制exceptfds
    if (exceptfds)
    {
        if (!lwp_user_accessable((void *)exceptfds, sizeof *exceptfds))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        kexceptfds = (fd_set *)kmem_get(sizeof *kexceptfds);
        if (!kexceptfds)
        {
            SET_ERRNO(EINVAL);
            goto quit;
        }
        lwp_get_from_user(kexceptfds, exceptfds, sizeof *kexceptfds);
    }

    // 处理超时参数
    if (timeout_ts)
    {
        struct timespec ktimeout_ts;
        
        if (!lwp_user_accessable((void *)timeout_ts, sizeof(struct timespec)))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        
        lwp_get_from_user(&ktimeout_ts, (void *)timeout_ts, sizeof(struct timespec));
        
        // 将timespec转换为timeval
        timeout.tv_sec = ktimeout_ts.tv_sec;
        timeout.tv_usec = ktimeout_ts.tv_nsec / 1000;
        ptimeout = &timeout;
    }

    // 处理信号掩码
    if (sigmask)
    {
        if (!lwp_user_accessable((void *)sigmask, sizeof(sigset_t)))
        {
            SET_ERRNO(EFAULT);
            goto quit;
        }
        
        ksigmask = (sigset_t *)kmem_get(sizeof(sigset_t));
        if (!ksigmask)
        {
            SET_ERRNO(ENOMEM);
            goto quit;
        }
        
        lwp_get_from_user(ksigmask, (void *)sigmask, sizeof(sigset_t));
        
        // 保存旧的信号掩码，设置新的信号掩码
        rt_thread_t thread = rt_thread_self();
        rt_memcpy(&old_sigmask, &thread->sig_mask, sizeof(sigset_t));
        rt_memcpy(&thread->sig_mask, ksigmask, sizeof(sigset_t));
    }

    // 调用select函数
    ret = select(nfds, kreadfds, kwritefds, kexceptfds, ptimeout);
    
    // 恢复旧的信号掩码
    if (sigmask)
    {
        rt_thread_t thread = rt_thread_self();
        rt_memcpy(&thread->sig_mask, &old_sigmask, sizeof(sigset_t));
    }

    // 将结果复制回用户空间
    if (ret > 0)
    {
        if (kreadfds)
        {
            lwp_put_to_user(readfds, kreadfds, sizeof *kreadfds);
        }
        if (kwritefds)
        {
            lwp_put_to_user(writefds, kwritefds, sizeof *kwritefds);
        }
        if (kexceptfds)
        {
            lwp_put_to_user(exceptfds, kexceptfds, sizeof *kexceptfds);
        }
    }

quit:
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    // 释放内核内存
    if (kreadfds)
    {
        kmem_put(kreadfds);
    }
    if (kwritefds)
    {
        kmem_put(kwritefds);
    }
    if (kexceptfds)
    {
        kmem_put(kexceptfds);
    }
    if (ksigmask)
    {
        kmem_put(ksigmask);
    }
    
    return ret;
}

sysret_t sys_copy_file_range(int in_fd, off_t *in_off, int out_fd, off_t *out_off, size_t count, unsigned int _flags)
{
    ssize_t ret = 0;
    ssize_t total_copied = 0;
    off_t original_in_pos = -1, original_out_pos = -1;
    off_t in_pos, out_pos;
    
    if (count == 0)
    {
        return 0;
    }

    original_in_pos = lseek(in_fd, 0, SEEK_CUR);
    original_out_pos = lseek(out_fd, 0, SEEK_CUR);
    if (original_in_pos < 0 || original_out_pos < 0) 
    {
        return GET_ERRNO();
    }
    
    in_pos  = original_in_pos;
    out_pos = original_out_pos;
    
    if (in_off != RT_NULL)
    {
        if (!lwp_user_accessable(in_off, sizeof(off_t)))
        {
            return -EFAULT;
        }
        
        lwp_get_from_user(&in_pos, in_off, sizeof(off_t));
    }

    if (out_off != RT_NULL)
    {
        if (!lwp_user_accessable(out_off, sizeof(off_t)))
        {
            return -EFAULT;
        }
        
        lwp_get_from_user(&out_pos, out_off, sizeof(off_t));
    }

    if (lseek(in_fd, in_pos, SEEK_SET) < 0)
    {
        return GET_ERRNO();
    }

    if (lseek(out_fd, out_pos, SEEK_SET) < 0)
    {
        lseek(in_fd, original_in_pos, SEEK_SET);
        return GET_ERRNO();
    }

    char buffer[1024];
    const size_t buffer_size = sizeof(buffer);

    while (total_copied < count)
    {
        size_t to_read = count - total_copied;
        if (to_read > buffer_size)
        {
            to_read = buffer_size;
        }

        ssize_t bytes_read = read(in_fd, buffer, to_read);
        if (bytes_read < 0)
        {
            ret = GET_ERRNO();
            break;
        }
        if (bytes_read == 0)
        {
            break;
        }

        ssize_t bytes_written = write(out_fd, buffer, bytes_read);
        if (bytes_written < 0)
        {
            ret = GET_ERRNO();
            break;
        }
        if (bytes_written != bytes_read)
        {
            ret = -EIO;
            break;
        }

        total_copied += bytes_written;
    }

    if (ret >= 0)
    {
        if (in_off != RT_NULL)
        {
            off_t current_in_pos = lseek(in_fd, 0, SEEK_CUR);
            if (current_in_pos >= 0)
            {
                lwp_put_to_user(in_off, &current_in_pos, sizeof(off_t));
            }
            lseek(in_fd, original_in_pos, SEEK_SET);
        }
        
        if (out_off != RT_NULL)
        {
            off_t current_out_pos = lseek(out_fd, 0, SEEK_CUR);
            if (current_out_pos >= 0)
            {
                lwp_put_to_user(out_off, &current_out_pos, sizeof(off_t));
            }
            lseek(out_fd, original_out_pos, SEEK_SET);
        }
        
        ret = total_copied;
    }

    return ret;
}
