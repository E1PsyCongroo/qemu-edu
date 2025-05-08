#include "rtdef.h"
#include "syscall_generic.h"
#include "lwp_sys_socket.h"
#include "lwp_user_mm.h"
#include "sys/socket.h"
#include "sal_netdb.h"

#if defined(RT_USING_LWIP) || defined(SAL_USING_UNET)
static void sockaddr_tolwip(const struct musl_sockaddr *std, struct sockaddr *lwip)
{
    if (std && lwip)
    {
        lwip->sa_len    = sizeof(*lwip);
        lwip->sa_family = (sa_family_t)std->sa_family;
        memcpy(lwip->sa_data, std->sa_data, sizeof(lwip->sa_data));
    }
}

static void sockaddr_tomusl(const struct sockaddr *lwip, struct musl_sockaddr *std)
{
    if (std && lwip)
    {
        std->sa_family = (uint16_t)lwip->sa_family;
        memcpy(std->sa_data, lwip->sa_data, sizeof(std->sa_data));
    }
}
#endif

static void *kmem_get(size_t size)
{
    return rt_malloc(size);
}

static void kmem_put(void *kptr)
{
    rt_free(kptr);
}

#ifdef RT_USING_SAL
/* network interfaces */

/**
 * @brief Accepts a connection on a socket.
 *
 * This system call is used to accept a pending connection request on a socket. It extracts the
 * first connection request from the incoming queue, creates a new socket for the connection,
 * and stores the address information of the remote peer in the provided address structure.
 * The original socket must be a listening socket that has been previously bound and set to listen
 * for incoming connections.
 *
 * @param[in]  socket    The listening socket file descriptor that is waiting for incoming connections.
 *                       This socket must be in a listening state, created using `sys_socket` and
 *                       bound to an address using `sys_bind`.
 * @param[out] addr      A pointer to a `musl_sockaddr` structure where the address of the connecting
 *                       client will be stored. The structure is populated with information such as
 *                       the client's IP address and port number.
 * @param[in,out] addrlen A pointer to a socklen_t variable that specifies the size of the `addr`
 *                        structure on input. On output, it will contain the actual size of the
 *                        address returned in `addr`.
 *
 * @return sysret_t      Returns a socket descriptor for the new connection on success, or
 *                        `SYSRET_ERROR` on failure:
 *                        - On success: A new socket descriptor that can be used for further
 *                          communication with the connected peer.
 *                        - On failure: A negative error code indicating the reason for the failure.
 *
 * @note The socket passed as `socket` must be in a listening state and ready to accept incoming
 *       connections. The `addr` structure is populated with the client's address details, which can
 *       be used for further operations, such as identifying the client.
 *
 * @warning Ensure that the `addr` structure is sufficiently large to hold the address information.
 *          The `addrlen` parameter must be set to the size of the `musl_sockaddr` structure before
 *          calling this function. Calling the function with an incorrectly sized `addrlen` may lead
 *          to buffer overflows or undefined behavior.
 */
sysret_t sys_accept(int socket, struct musl_sockaddr *addr, socklen_t *addrlen)
{
    int                  ret = -1;
    struct sockaddr      ksa;
    struct musl_sockaddr kmusladdr;
    socklen_t            uaddrlen;
    socklen_t            kaddrlen;

    if (addr)
    {
        if (!lwp_user_accessable(addrlen, sizeof(socklen_t)))
        {
            return -EFAULT;
        }
        lwp_get_from_user(&uaddrlen, addrlen, sizeof(socklen_t));
        if (!uaddrlen)
        {
            return -EINVAL;
        }

        if (!lwp_user_accessable(addr, uaddrlen))
        {
            return -EFAULT;
        }
    }

    kaddrlen = sizeof(struct sockaddr);
    ret      = accept(socket, &ksa, &kaddrlen);
    if (ret >= 0)
    {
        if (addr)
        {
            sockaddr_tomusl(&ksa, &kmusladdr);
            if (uaddrlen > sizeof(struct musl_sockaddr))
            {
                uaddrlen = sizeof(struct musl_sockaddr);
            }
            lwp_put_to_user(addr, &kmusladdr, uaddrlen);
            lwp_put_to_user(addrlen, &uaddrlen, sizeof(socklen_t));
        }
    }
    return ret;
}

/**
 * @brief Binds a socket to a local address.
 *
 * This system call binds a socket to a specific local address and port. The socket must be created
 * using `sys_socket` before it can be bound. The `bind` operation allows the application to associate
 * a socket with a specific address, such as an IP address and port number, which can then be used
 * for sending or receiving data.
 *
 * @param[in]  socket  The socket descriptor to which the address will be bound. This socket must
 *                     be created using `sys_socket` and should not already be bound to another address.
 * @param[in]  name    A pointer to a `musl_sockaddr` structure that contains the address to which
 *                     the socket will be bound. This can represent an IP address and port number.
 * @param[in]  namelen The size of the `musl_sockaddr` structure in bytes. This value should be set
 *                     to the actual size of the `name` structure before calling this function.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code on failure.
 *
 * @note The `socket` must be created before calling this function, and the address provided in `name`
 *       should be a valid local address for the socket. This operation is typically used for server-side
 *       sockets that listen for incoming connections or for any socket that needs to specify its local
 *       address before communication.
 *
 * @warning If the specified address is already in use by another socket or if the socket type is incompatible
 *          with the address, the function will return an error. Ensure that the address is not in use and is
 *          valid for the socket type.
 */
sysret_t sys_bind(int socket, const struct musl_sockaddr *name, socklen_t namelen)
{
    rt_err_t             ret = 0;
    struct sockaddr      sa;
    struct sockaddr_un   un_addr;
    struct musl_sockaddr kname;
    rt_uint16_t          family = 0;

    if (!lwp_user_accessable((void *)name, namelen))
    {
        return -EFAULT;
    }

    lwp_get_from_user(&family, (void *)name, 2);
    if (family == AF_UNIX)
    {
        lwp_get_from_user(&un_addr, (void *)name, sizeof(struct sockaddr_un));
        ret = bind(socket, (struct sockaddr *)&un_addr, namelen);
    }
    else if (family == AF_NETLINK)
    {
        lwp_get_from_user(&sa, (void *)name, namelen);
        ret = bind(socket, &sa, namelen);
    }
    else
    {
        lwp_get_from_user(&kname, (void *)name, namelen);
        sockaddr_tolwip(&kname, &sa);
        ret = bind(socket, &sa, namelen);
    }

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Shuts down part of a full-duplex connection.
 *
 * This system call disables further send or receive operations on a socket. The `how` parameter
 * specifies which part of the connection should be shut down. This operation is typically used
 * when the application no longer needs to send or receive data, but wants to keep the connection open
 * for other purposes (e.g., receiving shutdown acknowledgment).
 *
 * @param[in]  socket  The socket descriptor to be shut down. This socket must be an open socket that
 *                     has been created using `sys_socket`.
 * @param[in]  how     The shutdown behavior:
 *                     - `SHUT_RD`: Disables further receives on the socket. The application can no longer
 *                       receive data from this socket.
 *                     - `SHUT_WR`: Disables further sends on the socket. The application can no longer
 *                       send data through this socket.
 *                     - `SHUT_RDWR`: Disables both sends and receives on the socket. The socket is
 *                       fully shut down for communication.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code (e.g., `SYSRET_ERROR`) on failure.
 *
 * @note The `socket` should be open and in a connected state when calling this function. The `how`
 *       parameter determines which part of the connection is to be shut down, allowing for finer control
 *       over communication termination.
 *
 * @warning Once a socket is shut down with `SHUT_RD`, no further data can be received on it. Similarly,
 *          after `SHUT_WR`, no more data can be sent. Calling `sys_shutdown` with incompatible `how` values
 *          or on an invalid socket may result in errors.
 */
sysret_t sys_shutdown(int socket, int how)
{
    return shutdown(socket, how);
}

/**
 * @brief Retrieves the address of the peer connected to a socket.
 *
 * This system call retrieves the address of the peer (remote endpoint) that is connected to the specified
 * socket. The socket must be connected (i.e., for stream-oriented protocols such as TCP). The address
 * of the peer is stored in the `name` structure, and the size of the structure is updated in `namelen`.
 *
 * @param[in]  socket    The socket descriptor of the connected socket. This socket must be in a connected
 *                       state (e.g., after a successful `sys_connect` or `sys_accept` call).
 * @param[out] name      A pointer to a `musl_sockaddr` structure where the address of the peer will be
 *                       stored. This structure will be populated with the peer's IP address and port number.
 * @param[in,out] namelen A pointer to a `socklen_t` variable that specifies the size of the `name` structure
 *                        on input. On output, it will contain the actual size of the address returned in `name`.
 *
 * @return sysret_t      Returns `SYSRET_OK` on success, or a negative error code on failure.
 *
 * @note The `socket` must be in a connected state when calling this function. The `name` structure will
 *       contain the peer's address information, which can be used for logging, debugging, or further
 *       communication.
 *
 * @warning Ensure that the `name` structure is sufficiently large to hold the peer's address information.
 *          The `namelen` parameter must be set to the size of the `name` structure before calling this function.
 *          Failing to provide a correctly sized `namelen` could result in buffer overflows or undefined behavior.
 */
sysret_t sys_getpeername(int socket, struct musl_sockaddr *name, socklen_t *namelen)
{
    int                  ret = -1;
    struct sockaddr      sa;
    struct musl_sockaddr kname;
    socklen_t            unamelen;
    socklen_t            knamelen;

    if (!lwp_user_accessable(namelen, sizeof(socklen_t)))
    {
        return -EFAULT;
    }
    lwp_get_from_user(&unamelen, namelen, sizeof(socklen_t));
    if (!unamelen)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable(name, unamelen))
    {
        return -EFAULT;
    }

    knamelen = sizeof(struct sockaddr);
    ret      = getpeername(socket, &sa, &knamelen);

    if (ret == 0)
    {
        sockaddr_tomusl(&sa, &kname);
        if (unamelen > sizeof(struct musl_sockaddr))
        {
            unamelen = sizeof(struct musl_sockaddr);
        }
        lwp_put_to_user(name, &kname, unamelen);
        lwp_put_to_user(namelen, &unamelen, sizeof(socklen_t));
    }
    else
    {
        ret = GET_ERRNO();
    }

    return ret;
}

/**
 * @brief Retrieves the local address of the socket.
 *
 * This system call retrieves the local address (local endpoint) that is bound to the specified socket.
 * The socket must be created and, if necessary, bound to a local address using `sys_bind`. The address
 * of the local endpoint is stored in the `name` structure, and the size of the structure is updated in `namelen`.
 *
 * @param[in]  socket    The socket descriptor of the socket. This socket must be created and, if required,
 *                       bound to a local address.
 * @param[out] name      A pointer to a `musl_sockaddr` structure where the local address of the socket will
 *                       be stored. This structure will be populated with the local IP address and port number.
 * @param[in,out] namelen A pointer to a `socklen_t` variable that specifies the size of the `name` structure
 *                        on input. On output, it will contain the actual size of the address returned in `name`.
 *
 * @return sysret_t      Returns `0` on success, or a negative error code on failure.
 *
 * @note The `socket` must be created and, if needed, bound to a local address using `sys_bind`.
 *       The `name` structure will contain the local address of the socket, which can be used for logging,
 *       debugging, or further communication.
 *
 * @warning Ensure that the `name` structure is sufficiently large to hold the local address information.
 *          The `namelen` parameter must be set to the size of the `name` structure before calling this function.
 *          Failing to provide a correctly sized `namelen` could result in buffer overflows or undefined behavior.
 */
sysret_t sys_getsockname(int socket, struct musl_sockaddr *name, socklen_t *namelen)
{
    int                  ret = -1;
    struct sockaddr      sa;
    struct musl_sockaddr kname;
    socklen_t            unamelen;
    socklen_t            knamelen;

    if (!lwp_user_accessable(namelen, sizeof(socklen_t)))
    {
        return -EFAULT;
    }
    lwp_get_from_user(&unamelen, namelen, sizeof(socklen_t));
    if (!unamelen)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable(name, unamelen))
    {
        return -EFAULT;
    }

    knamelen = sizeof(struct sockaddr);
    ret      = getsockname(socket, &sa, &knamelen);
    if (ret == 0)
    {
        sockaddr_tomusl(&sa, &kname);
        if (unamelen > sizeof(struct musl_sockaddr))
        {
            unamelen = sizeof(struct musl_sockaddr);
        }
        lwp_put_to_user(name, &kname, unamelen);
        lwp_put_to_user(namelen, &unamelen, sizeof(socklen_t));
    }
    else
    {
        ret = GET_ERRNO();
    }
    return ret;
}

static void convert_sockopt(int *level, int *optname)
{
    if (*level == INTF_SOL_SOCKET)
    {
        *level = IMPL_SOL_SOCKET;

        switch (*optname)
        {
        case INTF_SO_REUSEADDR:
            *optname = IMPL_SO_REUSEADDR;
            break;
        case INTF_SO_KEEPALIVE:
            *optname = IMPL_SO_KEEPALIVE;
            break;
        case INTF_SO_BROADCAST:
            *optname = IMPL_SO_BROADCAST;
            break;
        case INTF_SO_ACCEPTCONN:
            *optname = IMPL_SO_ACCEPTCONN;
            break;
        case INTF_SO_DONTROUTE:
            *optname = IMPL_SO_DONTROUTE;
            break;
        case INTF_SO_LINGER:
            *optname = IMPL_SO_LINGER;
            break;
        case INTF_SO_OOBINLINE:
            *optname = IMPL_SO_OOBINLINE;
            break;
        case INTF_SO_REUSEPORT:
            *optname = IMPL_SO_REUSEPORT;
            break;
        case INTF_SO_SNDBUF:
            *optname = IMPL_SO_SNDBUF;
            break;
        case INTF_SO_RCVBUF:
            *optname = IMPL_SO_RCVBUF;
            break;
        case INTF_SO_SNDLOWAT:
            *optname = IMPL_SO_SNDLOWAT;
            break;
        case INTF_SO_RCVLOWAT:
            *optname = IMPL_SO_RCVLOWAT;
            break;
        case INTF_SO_SNDTIMEO:
            *optname = IMPL_SO_SNDTIMEO;
            break;
        case INTF_SO_RCVTIMEO:
            *optname = IMPL_SO_RCVTIMEO;
            break;
        case INTF_SO_ERROR:
            *optname = IMPL_SO_ERROR;
            break;
        case INTF_SO_TYPE:
            *optname = IMPL_SO_TYPE;
            break;
        case INTF_SO_NO_CHECK:
            *optname = IMPL_SO_NO_CHECK;
            break;
        case INTF_SO_BINDTODEVICE:
            *optname = IMPL_SO_BINDTODEVICE;
            break;
        case INTF_SO_TIMESTAMPNS:
            *optname = IMPL_SO_TIMESTAMPNS;
            break;
        case INTF_SO_TIMESTAMPING:
            *optname = IMPL_SO_TIMESTAMPING;
            break;
        case INTF_SO_SELECT_ERR_QUEUE:
            *optname = IMPL_SO_SELECT_ERR_QUEUE;
            break;

        /*
                * SO_DONTLINGER (*level = ((int)(~SO_LINGER))),
                * SO_USELOOPBACK (*level = 0x0040) and
                * SO_CONTIMEO (*level = 0x1009) are not supported for now.
                */
        default:
            *optname = 0;
            break;
        }
        return;
    }

    if (*level == INTF_IPPROTO_IP)
    {
        *level = IMPL_IPPROTO_IP;

        switch (*optname)
        {
        case INTF_IP_TTL:
            *optname = IMPL_IP_TTL;
            break;
        case INTF_IP_TOS:
            *optname = IMPL_IP_TOS;
            break;
        case INTF_IP_MULTICAST_TTL:
            *optname = IMPL_IP_MULTICAST_TTL;
            break;
        case INTF_IP_MULTICAST_IF:
            *optname = IMPL_IP_MULTICAST_IF;
            break;
        case INTF_IP_MULTICAST_LOOP:
            *optname = IMPL_IP_MULTICAST_LOOP;
            break;
        case INTF_IP_ADD_MEMBERSHIP:
            *optname = IMPL_IP_ADD_MEMBERSHIP;
            break;
        case INTF_IP_DROP_MEMBERSHIP:
            *optname = IMPL_IP_DROP_MEMBERSHIP;
            break;
        default:
            break;
        }
    }

    if (*level == INTF_IPPROTO_TCP)
    {
        *level = IMPL_IPPROTO_TCP;

        switch (*optname)
        {
        case INTF_TCP_NODELAY:
            *optname = IMPL_TCP_NODELAY;
            break;
        case INTF_TCP_KEEPALIVE:
            *optname = IMPL_TCP_KEEPALIVE;
            break;
        case INTF_TCP_KEEPIDLE:
            *optname = IMPL_TCP_KEEPIDLE;
            break;
        case INTF_TCP_KEEPINTVL:
            *optname = IMPL_TCP_KEEPINTVL;
            break;
        case INTF_TCP_KEEPCNT:
            *optname = IMPL_TCP_KEEPCNT;
            break;
        default:
            break;
        }
        return;
    }

    if (*level == INTF_IPPROTO_IPV6)
    {
        *level = IMPL_IPPROTO_IPV6;

        switch (*optname)
        {
        case INTF_IPV6_V6ONLY:
            *optname = IMPL_IPV6_V6ONLY;
            break;
        default:
            break;
        }
        return;
    }
}

/**
 * @brief Retrieves the value of a socket option.
 *
 * This system call retrieves the current value of a socket option for the specified socket. The socket
 * options allow fine-grained control over various aspects of socket behavior, such as timeouts, buffering,
 * and connection settings. The option value is stored in the `optval` buffer, and the size of the buffer
 * is specified by the `optlen` parameter.
 *
 * @param[in]  socket    The socket descriptor for which the option value is being retrieved. The socket
 *                       must be valid and open.
 * @param[in]  level     The level at which the option is defined. Typically, this is `SOL_SOCKET` for general
 *                       socket options, or a protocol-specific level (e.g., `IPPROTO_TCP` for TCP options).
 * @param[in]  optname   The option name. This specifies which socket option to retrieve (e.g., `SO_RCVBUF`
 *                       for receive buffer size or `SO_RCVBUF` for send buffer size).
 * @param[out] optval    A pointer to a buffer where the option value will be stored. The buffer's type depends
 *                       on the option being retrieved.
 * @param[in,out] optlen A pointer to a `socklen_t` variable that specifies the size of the `optval` buffer on
 *                       input. On output, it will contain the actual size of the option value retrieved.
 *
 * @return sysret_t      Returns `0` on success, or a negative error code on failure.
 *
 * @note The `socket` must be valid and open when calling this function. The `level` and `optname` parameters
 *       define the specific option to be retrieved. The `optval` buffer will contain the option value after
 *       the function call, and `optlen` will be updated to reflect the size of the retrieved value.
 *
 * @warning Ensure that the `optval` buffer is large enough to hold the value for the specified option.
 *          The `optlen` parameter must be set to the correct size of the buffer before calling this function.
 *          Failing to provide a correctly sized buffer could result in undefined behavior or buffer overflows.
 */
sysret_t sys_getsockopt(int socket, int level, int optname, void *optval, socklen_t *optlen)
{
    int       ret     = 0;
    socklen_t koptlen = 0;
    void     *koptval = RT_NULL;

    if (!lwp_user_accessable((void *)optlen, sizeof(uint32_t)))
        return -EFAULT;

    if (lwp_get_from_user(&koptlen, optlen, sizeof(uint32_t)) != sizeof(uint32_t))
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)optval, koptlen))
        return -EFAULT;

    koptval = kmem_get(koptlen);
    if (koptval == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(koptval, optval, koptlen) != koptlen)
    {
        kmem_put(koptval);
        return -EINVAL;
    }

    convert_sockopt(&level, &optname);
    ret = getsockopt(socket, level, optname, koptval, &koptlen);

    lwp_put_to_user((void *)optval, koptval, koptlen);
    lwp_put_to_user((void *)optlen, &koptlen, sizeof(uint32_t));

    kmem_put(koptval);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Sets the value of a socket option.
 *
 * This system call sets a socket option for the specified socket. Socket options control various aspects
 * of socket behavior, such as timeouts, buffer sizes, or connection parameters. The option value is
 * provided in the `optval` buffer, and its length is specified by the `optlen` parameter.
 *
 * @param[in]  socket    The socket descriptor for which the option is being set. The socket must be valid and open.
 * @param[in]  level     The level at which the option is defined. This can be `SOL_SOCKET` for general socket options,
 *                       or a protocol-specific level (e.g., `IPPROTO_TCP` for TCP options).
 * @param[in]  optname   The option name. This specifies which socket option to set (e.g., `SO_RCVBUF` for receive buffer size).
 * @param[in]  optval    A pointer to the buffer that contains the option value to set. The format of this buffer depends
 *                       on the option being set.
 * @param[in]  optlen    The size of the `optval` buffer. This specifies the length of the data to be used when setting
 *                       the option value.
 *
 * @return sysret_t      Returns `0` on success, or a negative error code on failure:
 *
 * @note The `socket` must be valid and open. The `level` and `optname` parameters define the specific option to be set,
 *       and the `optval` buffer should contain the appropriate value for that option. The `optlen` parameter must
 *       match the size of the `optval` buffer.
 *
 * @warning Ensure that the `optval` buffer contains valid data for the specified option. The `optlen` parameter must be
 *          set to the correct size of the `optval` buffer before calling this function. Failing to provide a correctly
 *          sized buffer could result in undefined behavior or errors.
 */
sysret_t sys_setsockopt(int socket, int level, int optname, const void *optval, socklen_t optlen)
{
    int   ret;
    void *koptval = RT_NULL;

    if (!lwp_user_accessable((void *)optval, optlen))
        return -EFAULT;

    koptval = kmem_get(optlen);
    if (koptval == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(koptval, (void *)optval, optlen) != optlen)
    {
        kmem_put(koptval);
        return -EINVAL;
    }

    convert_sockopt(&level, &optname);
    ret = setsockopt(socket, level, optname, koptval, optlen);

    kmem_put(koptval);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Establishes a connection to a remote socket.
 *
 * This system call attempts to establish a connection to a remote socket specified by the `name` parameter.
 * It is typically used for client-side socket operations to connect to a server. The connection is established
 * by using the specified socket descriptor and the address of the remote server.
 *
 * @param[in]  socket   The socket descriptor for the connection attempt. The socket must be valid and in a
 *                      `SOCK_STREAM` or `SOCK_DGRAM` state, depending on the protocol.
 * @param[in]  name     A pointer to a `sockaddr` structure containing the address of the remote host. This address
 *                      must include the correct IP address and port number for the connection.
 * @param[in]  namelen  The size of the `sockaddr` structure pointed to by `name`. This should match the size
 *                      of the address structure (e.g., `sizeof(struct sockaddr_in)` for IPv4).
 *
 * @return sysret_t     Returns `0` on success, or a negative error code on failure:
 *
 * @note This function may block if the connection is being established, depending on the socket's configuration.
 *       For non-blocking sockets, it will return immediately, even if the connection has not been established.
 *
 * @warning The `socket` must be of a valid type (e.g., `SOCK_STREAM` for TCP or `SOCK_DGRAM` for UDP).
 *          The `name` parameter must point to a valid `sockaddr` structure that contains a correctly formatted address.
 */
sysret_t sys_connect(int socket, const struct musl_sockaddr *name, socklen_t namelen)
{
    int                  ret    = 0;
    rt_uint16_t          family = 0;
    struct sockaddr      sa;
    struct musl_sockaddr kname;
    struct sockaddr_un   addr_un;

    if (!lwp_user_accessable((void *)name, namelen))
    {
        return -EFAULT;
    }

    lwp_get_from_user(&family, (void *)name, 2);
    if (family == AF_UNIX)
    {
        if (!lwp_user_accessable((void *)name, sizeof(struct sockaddr_un)))
        {
            return -EFAULT;
        }

        lwp_get_from_user(&addr_un, (void *)name, sizeof(struct sockaddr_un));
        ret = connect(socket, (struct sockaddr *)(&addr_un), namelen);
    }
    else
    {
        lwp_get_from_user(&kname, (void *)name, namelen);
        sockaddr_tolwip(&kname, &sa);
        ret = connect(socket, &sa, namelen);
    }

    return ret;
}

/**
 * @brief Prepares a socket to accept incoming connection requests.
 *
 * This system call marks a socket as a passive socket, indicating that it will be used to accept
 * incoming connection requests. It is typically used on server-side sockets after binding a
 * local address and port using `sys_bind()`.
 *
 * @param[in]  socket   The socket descriptor to be set up for listening. The socket must be valid
 *                      and of type `SOCK_STREAM` (for TCP connections).
 * @param[in]  backlog  The maximum number of pending connections that can be queued. This value
 *                      is system-dependent and may be limited to a lower maximum.
 *
 * @return sysret_t     Returns `0` on success, or a negative error code on failure.
 *
 * @note Before calling this function, the socket must be bound to a local address and port using
 *       `sys_bind()`. Only sockets of type `SOCK_STREAM` can be used for listening. The actual
 *       maximum queue length may be less than the specified `backlog` value, depending on system limits.
 *
 * @warning Ensure that the socket is properly initialized, bound, and of the correct type before calling this function.
 *          Failure to do so will result in undefined behavior or errors.
 */
sysret_t sys_listen(int socket, int backlog)
{
    return listen(socket, backlog);
}

#define MUSLC_MSG_OOB      0x0001
#define MUSLC_MSG_PEEK     0x0002
#define MUSLC_MSG_DONTWAIT 0x0040
#define MUSLC_MSG_WAITALL  0x0100
#define MUSLC_MSG_MORE     0x8000

static int netflags_muslc_2_lwip(int flags)
{
    int flgs = 0;

    if (flags & MUSLC_MSG_PEEK)
    {
        flgs |= MSG_PEEK;
    }
    if (flags & MUSLC_MSG_WAITALL)
    {
        flgs |= MSG_WAITALL;
    }
    if (flags & MUSLC_MSG_OOB)
    {
        flgs |= MSG_OOB;
    }
    if (flags & MUSLC_MSG_DONTWAIT)
    {
        flgs |= MSG_DONTWAIT;
    }
    if (flags & MUSLC_MSG_MORE)
    {
        flgs |= MSG_MORE;
    }
    if (flags & MSG_ERRQUEUE)
    {
        flgs |= MSG_ERRQUEUE;
    }

    return flgs;
}

#ifdef ARCH_MM_MMU
static int copy_msghdr_from_user(struct msghdr *kmsg, struct msghdr *umsg,
                                 struct iovec **out_iov, void **out_msg_control)
{
    size_t        iovs_size;
    struct iovec *uiov, *kiov;
    size_t        iovs_buffer_size = 0;
    void         *iovs_buffer;

    if (!lwp_user_accessable(umsg, sizeof(*umsg)))
    {
        return -EFAULT;
    }

    lwp_get_from_user(kmsg, umsg, sizeof(*kmsg));

    iovs_size = sizeof(*kmsg->msg_iov) * kmsg->msg_iovlen;
    if (!lwp_user_accessable(kmsg->msg_iov, iovs_size))
    {
        return -EFAULT;
    }

    /* user and kernel */
    kiov = kmem_get(iovs_size * 2);
    if (!kiov)
    {
        return -ENOMEM;
    }

    uiov = (void *)kiov + iovs_size;
    lwp_get_from_user(uiov, kmsg->msg_iov, iovs_size);

    if (out_iov)
    {
        *out_iov = uiov;
    }
    kmsg->msg_iov = kiov;

    for (int i = 0; i < kmsg->msg_iovlen; ++i)
    {
        /*
         * We MUST check we can copy data to user after socket done in uiov
         * otherwise we will be lost the messages from the network!
         */
        if (!lwp_user_accessable(uiov->iov_base, uiov->iov_len))
        {
            kmem_put(kmsg->msg_iov);

            return -EPERM;
        }

        iovs_buffer_size += uiov->iov_len;
        kiov->iov_len     = uiov->iov_len;

        ++kiov;
        ++uiov;
    }

    /* msg_iov and msg_control */
    iovs_buffer = kmem_get(iovs_buffer_size + kmsg->msg_controllen);

    if (!iovs_buffer)
    {
        kmem_put(kmsg->msg_iov);

        return -ENOMEM;
    }

    kiov = kmsg->msg_iov;

    for (int i = 0; i < kmsg->msg_iovlen; ++i)
    {
        kiov->iov_base  = iovs_buffer;
        iovs_buffer    += kiov->iov_len;
        ++kiov;
    }

    *out_msg_control = kmsg->msg_control;
    /* msg_control is the end of the iovs_buffer */
    kmsg->msg_control = iovs_buffer;

    return 0;
}
#endif /* ARCH_MM_MMU */

/**
 * @brief Receives a message from a socket using a message header structure.
 *
 * This system call is used to receive data and associated metadata from a socket.
 * It supports both stream-oriented and message-oriented sockets and allows control
 * over the behavior of the receiving operation via the `flags` parameter.
 *
 * @param[in]  socket   The socket descriptor from which the message will be received.
 *                      The socket must be in a valid and connected state for stream-oriented
 *                      sockets or bound for message-oriented sockets.
 * @param[out] msg      A pointer to an `msghdr` structure that specifies message buffers and
 *                      will receive the incoming data. The structure also stores ancillary
 *                      data for advanced socket operations.
 * @param[in]  flags    Modifiers that control the behavior of the receive operation. Common
 *                      flags include:
 *                       - `MSG_PEEK`: Peek at the incoming data without removing it from the queue.
 *                       - `MSG_WAITALL`: Wait for the full request to be satisfied before returning.
 *                       - `MSG_DONTWAIT`: Perform a non-blocking receive operation.
 *
 * @return sysret_t     Returns `0` on success, or a negative error code on failure.
 *
 * @note The `msghdr` structure should be initialized properly, including setting up buffers for
 *       receiving the data. The function can return fewer bytes than expected depending on socket
 *       type and flags. For stream-oriented sockets, partial data may be received.
 *
 * @warning The `socket` must be valid and in an appropriate state. If the socket is non-blocking
 *          and no data is available, the function will return immediately.
 *
 * @see sys_sendmsg()
 */
sysret_t sys_recvmsg(int socket, struct msghdr *msg, int flags)
{
    int           flgs, ret = -1;
    struct msghdr kmsg;
#ifdef ARCH_MM_MMU
    void         *msg_control;
    struct iovec *uiov, *kiov;
#endif

    if (!msg)
    {
        return -EPERM;
    }

    flgs = netflags_muslc_2_lwip(flags);

#ifdef ARCH_MM_MMU
    ret = copy_msghdr_from_user(&kmsg, msg, &uiov, &msg_control);

    if (!ret)
    {
        ret = recvmsg(socket, &kmsg, flgs);

        if (ret < 0)
        {
            goto _free_res;
        }

        kiov = kmsg.msg_iov;

        for (int i = 0; i < kmsg.msg_iovlen; ++i)
        {
            lwp_put_to_user(uiov->iov_base, kiov->iov_base, kiov->iov_len);

            ++kiov;
            ++uiov;
        }

        lwp_put_to_user(msg_control, kmsg.msg_control, kmsg.msg_controllen);
        lwp_put_to_user(&msg->msg_flags, &kmsg.msg_flags, sizeof(kmsg.msg_flags));

    _free_res:
        kmem_put(kmsg.msg_iov->iov_base);
        kmem_put(kmsg.msg_iov);
    }
#else
    rt_memcpy(&kmsg, msg, sizeof(kmsg));

    ret = recvmsg(socket, &kmsg, flgs);

    if (!ret)
    {
        msg->msg_flags = kmsg.msg_flags;
    }
#endif /* ARCH_MM_MMU */

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Receives data from a socket, optionally capturing the source address.
 *
 * This system call is used to receive data from a socket. For connectionless sockets, it also
 * retrieves the address of the sender. It supports both blocking and non-blocking operations
 * depending on the socket configuration and the specified flags.
 *
 * @param[in]  socket   The socket descriptor from which the data will be received. The socket
 *                      must be valid and appropriately configured (e.g., connected or bound).
 * @param[out] mem      A pointer to the buffer where the received data will be stored.
 * @param[in]  len      The maximum number of bytes to receive. This defines the size of the `mem` buffer.
 * @param[in]  flags    Modifiers that control the behavior of the receive operation. Common
 *                      flags include:
 *                       - `MSG_PEEK`: Peek at the incoming data without removing it from the queue.
 *                       - `MSG_WAITALL`: Wait for the full request to be satisfied before returning.
 *                       - `MSG_DONTWAIT`: Perform a non-blocking receive operation.
 * @param[out] from     A pointer to a `musl_sockaddr` structure that will hold the address of
 *                      the sender. This parameter can be `NULL` if the sender's address is not needed.
 * @param[in,out] fromlen A pointer to a `socklen_t` variable indicating the size of the `from` buffer.
 *                        On return, it will be updated with the actual size of the sender's address.
 *                        This parameter is ignored if `from` is `NULL`.
 *
 * @return sysret_t     Returns `0` on success, or a negative error code on failure:
 *
 * @note For stream-oriented sockets, this function behaves like `sys_recv()`, and the `from` and
 *       `fromlen` parameters are ignored. For datagram-oriented sockets, the function fills `from`
 *       with the address of the sender.
 *
 * @warning The `socket` must be valid and configured for receiving data. If the `mem` buffer is
 *          smaller than the received data, excess data may be discarded. In non-blocking mode,
 *          if no data is available, the function returns immediately.
 *
 * @see sys_sendto(), sys_recv()
 */
sysret_t sys_recvfrom(int socket, void *mem, size_t len, int flags,
                      struct musl_sockaddr *from, socklen_t *fromlen)
{
    int flgs = 0;
#ifdef ARCH_MM_MMU
    int   ret  = -1;
    void *kmem = RT_NULL;
#endif

    flgs = netflags_muslc_2_lwip(flags);
#ifdef ARCH_MM_MMU
    if (!len)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)mem, len))
    {
        return -EFAULT;
    }

    kmem = kmem_get(len);
    if (!kmem)
    {
        return -ENOMEM;
    }

    if (flags == 0x2)
    {
        flags = 0x1;
    }

    if (from)
    {
        struct sockaddr sa;

        ret = recvfrom(socket, kmem, len, flgs, &sa, fromlen);
        sockaddr_tomusl(&sa, from);
    }
    else
    {
        ret = recvfrom(socket, kmem, len, flgs, NULL, NULL);
    }

    if (ret > 0)
    {
        lwp_put_to_user(mem, kmem, len);
    }

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
#else
    int ret = -1;
    if (from)
    {
        struct sockaddr sa = {0};

        ret = recvfrom(socket, mem, len, flgs, &sa, fromlen);
        sockaddr_tomusl(&sa, from);
    }
    else
    {
        ret = recvfrom(socket, mem, len, flags, NULL, NULL);
    }
    return (ret < 0 ? GET_ERRNO() : ret);
#endif
}

/**
 * @brief Receives data from a connected socket.
 *
 * This system call is used to receive data from a socket that is in a connected state.
 * It supports various flags to modify the behavior of the receive operation.
 *
 * @param[in]  socket   The socket descriptor from which the data will be received.
 *                      The socket must be in a valid and connected state.
 * @param[out] mem      A pointer to the buffer where the received data will be stored.
 * @param[in]  len      The maximum number of bytes to receive. This defines the size of the `mem` buffer.
 * @param[in]  flags    Modifiers that control the behavior of the receive operation. Common flags include:
 *                       - `MSG_PEEK`: Peek at the incoming data without removing it from the queue.
 *                       - `MSG_WAITALL`: Wait for the full request to be satisfied before returning.
 *                       - `MSG_DONTWAIT`: Perform a non-blocking receive operation.
 *
 * @return sysret_t     Returns `0` on success, or a negative error code on failure.
 *
 * @note The function is designed for connected sockets, such as stream-oriented sockets (e.g., TCP).
 *       For datagram-oriented sockets (e.g., UDP), use `sys_recvfrom()` to capture the sender's address if needed.
 *
 * @warning The `socket` must be valid and in a connected state. If the `mem` buffer is smaller than the
 *          received data, excess data may be discarded. For non-blocking sockets, the function returns
 *          immediately if no data is available.
 *
 * @see sys_send(), sys_recvfrom()
 */
sysret_t sys_recv(int socket, void *mem, size_t len, int flags)
{
    int   flgs = 0;
    int   ret;
    void *kmem = RT_NULL;

    if (!lwp_user_accessable((void *)mem, len))
        return -EFAULT;

    kmem = kmem_get(sizeof(*kmem));
    if (kmem == RT_NULL)
    {
        return -ENOMEM;
    }

    flgs = netflags_muslc_2_lwip(flags);
    ret  = recvfrom(socket, kmem, len, flgs, NULL, NULL);

    lwp_put_to_user((void *)mem, kmem, len);
    kmem_put(kmem);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Sends a message from a socket using scatter-gather I/O.
 *
 * This system call sends data from multiple buffers specified in the `msghdr` structure. It is particularly
 * useful for advanced socket operations requiring ancillary data or scatter-gather I/O.
 *
 * @param[in] socket   The socket descriptor through which the data will be sent. The socket must be
 *                     valid and, for connection-oriented sockets, in a connected state.
 * @param[in] msg      A pointer to a `msghdr` structure that specifies the message to be sent. This structure includes:
 *                      - `msg_name`: Optional address of the target (used for connectionless sockets like UDP).
 *                      - `msg_namelen`: Length of the address in `msg_name`.
 *                      - `msg_iov`: An array of `iovec` structures pointing to the data buffers.
 *                      - `msg_iovlen`: The number of elements in the `msg_iov` array.
 *                      - `msg_control`: Optional ancillary data (e.g., file descriptors).
 *                      - `msg_controllen`: Length of the ancillary data.
 *                      - `msg_flags`: Flags for the message (e.g., end-of-record markers).
 * @param[in] flags    Flags that modify the behavior of the send operation. Common flags include:
 *                      - `MSG_DONTWAIT`: Perform a non-blocking send operation.
 *                      - `MSG_EOR`: Indicates the end of a record.
 *                      - `MSG_NOSIGNAL`: Prevent the function from raising `SIGPIPE` on errors.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code on failure.
 *
 * @note This function is versatile and supports both connection-oriented (e.g., TCP) and
 *       connectionless (e.g., UDP) sockets. For simpler use cases, consider using `sys_send()` or `sys_sendto()`.
 *
 * @warning The `socket` must be configured correctly for the intended communication. For non-blocking sockets,
 *          the function may return immediately if the send buffer is full. Ancillary data in `msg_control`
 *          must be formatted correctly to avoid undefined behavior.
 *
 * @see sys_send(), sys_sendto(), sys_recvmsg()
 */
sysret_t sys_sendmsg(int socket, const struct msghdr *msg, int flags)
{
    int           flgs, ret = -1;
    struct msghdr kmsg;
#ifdef ARCH_MM_MMU
    void         *msg_control;
    struct iovec *uiov, *kiov;
#endif
    if (!msg)
    {
        return -EPERM;
    }

    flgs = netflags_muslc_2_lwip(flags);

#ifdef ARCH_MM_MMU
    ret = copy_msghdr_from_user(&kmsg, (struct msghdr *)msg, &uiov, &msg_control);

    if (!ret)
    {
        kiov = kmsg.msg_iov;

        for (int i = 0; i < kmsg.msg_iovlen; ++i)
        {
            lwp_get_from_user(kiov->iov_base, uiov->iov_base, kiov->iov_len);

            ++kiov;
            ++uiov;
        }

        lwp_get_from_user(kmsg.msg_control, msg_control, kmsg.msg_controllen);

        ret = sendmsg(socket, &kmsg, flgs);

        kmem_put(kmsg.msg_iov->iov_base);
        kmem_put(kmsg.msg_iov);
    }
#else
    rt_memcpy(&kmsg, msg, sizeof(kmsg));

    ret = sendmsg(socket, &kmsg, flgs);

    if (!ret)
    {
        msg->msg_flags = kmsg.msg_flags;
    }
#endif /* ARCH_MM_MMU */

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Sends data to a specific address using a socket.
 *
 * This system call is used to send data from a socket to a specified address. It is commonly
 * used with connectionless sockets (e.g., UDP) but can also be used with connection-oriented
 * sockets if the destination address needs to be overridden.
 *
 * @param[in] socket   The socket descriptor used for sending data. It must be valid and
 *                     properly configured for communication.
 * @param[in] dataptr  A pointer to the buffer containing the data to be sent.
 * @param[in] size     The size, in bytes, of the data to be sent.
 * @param[in] flags    Flags that modify the behavior of the send operation. Common flags include:
 *                      - `MSG_DONTWAIT`: Perform a non-blocking send operation.
 *                      - `MSG_NOSIGNAL`: Prevent the function from raising `SIGPIPE` on errors.
 * @param[in] to       A pointer to a `musl_sockaddr` structure that specifies the destination address.
 *                     This parameter can be `NULL` if the socket is connection-oriented.
 * @param[in] tolen    The length of the address structure pointed to by `to`.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code on failure.
 *
 * @note For connectionless sockets (e.g., UDP), `to` and `tolen` must specify a valid destination address.
 *       For connection-oriented sockets (e.g., TCP), these parameters can be ignored if the connection
 *       is already established.
 *
 * @warning Ensure that the buffer size (`size`) matches the expected size for the data protocol in use.
 *          For non-blocking sockets, this function may return immediately if the send buffer is full.
 *
 * @see sys_send(), sys_sendmsg(), sys_recvfrom()
 */
sysret_t sys_sendto(int socket, const void *dataptr, size_t size, int flags,
                    const struct musl_sockaddr *to, socklen_t tolen)
{
    int flgs = 0;
#ifdef ARCH_MM_MMU
    int   ret  = -1;
    void *kmem = RT_NULL;
#endif

    flgs = netflags_muslc_2_lwip(flags);
#ifdef ARCH_MM_MMU
    if (!size)
    {
        return -EINVAL;
    }

    if (!lwp_user_accessable((void *)dataptr, size))
    {
        return -EFAULT;
    }

    kmem = kmem_get(size);
    if (!kmem)
    {
        return -ENOMEM;
    }

    lwp_get_from_user(kmem, (void *)dataptr, size);

    if (to)
    {
        struct sockaddr sa;
        sockaddr_tolwip(to, &sa);

        ret = sendto(socket, kmem, size, flgs, &sa, tolen);
    }
    else
    {
        ret = sendto(socket, kmem, size, flgs, NULL, tolen);
    }

    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    kmem_put(kmem);

    return ret;
#else
    int ret;
    if (to)
    {
        struct sockaddr sa;
        sockaddr_tolwip(to, &sa);

        ret = sendto(socket, dataptr, size, flgs, &sa, tolen);
    }
    else
    {
        ret = sendto(socket, dataptr, size, flgs, NULL, tolen);
    }
    return (ret < 0 ? GET_ERRNO() : ret);
#endif
}

/**
 * @brief Sends data over a connected socket.
 *
 * This system call sends data from the specified buffer through a connected socket. It is typically
 * used with connection-oriented sockets (e.g., TCP) but can also work with connectionless sockets
 * (e.g., UDP) if a connection is established using `sys_connect()`.
 *
 * @param[in] socket   The socket descriptor used for sending data. It must be a valid socket
 *                     and, for connection-oriented sockets, in a connected state.
 * @param[in] dataptr  A pointer to the buffer containing the data to be sent.
 * @param[in] size     The size, in bytes, of the data to be sent.
 * @param[in] flags    Flags that modify the behavior of the send operation. Common flags include:
 *                      - `MSG_DONTWAIT`: Perform a non-blocking send operation.
 *                      - `MSG_NOSIGNAL`: Prevent the function from raising `SIGPIPE` on errors.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code on failure.
 *
 * @note For connection-oriented sockets, the socket must already be connected using `sys_connect()` or
 *       `sys_accept()`. For connectionless sockets, use `sys_sendto()` to specify the destination address.
 *
 * @warning If the socket is in non-blocking mode and the send buffer is full, this function may return
 *          immediately with an error. Ensure that the size of the data (`size`) matches the protocol's
 *          expectations to avoid truncation or overflow issues.
 *
 * @see sys_sendto(), sys_sendmsg(), sys_recv()
 */
sysret_t sys_send(int socket, const void *dataptr, size_t size, int flags)
{
    int   flgs     = 0;
    int   ret      = 0;
    void *kdataptr = RT_NULL;

    if (!lwp_user_accessable((void *)dataptr, size))
        return -EFAULT;

    kdataptr = kmem_get(size);
    if (kdataptr == RT_NULL)
    {
        return -ENOMEM;
    }

    if (lwp_get_from_user(kdataptr, (void *)dataptr, size) != size)
    {
        kmem_put(kdataptr);
        return -EINVAL;
    }

    flgs = netflags_muslc_2_lwip(flags);
    ret  = sendto(socket, kdataptr, size, flgs, NULL, 0);

    kmem_put(kdataptr);

    return (ret < 0 ? GET_ERRNO() : ret);
}

/**
 * @brief Creates a new socket for communication.
 *
 * This system call creates a new socket endpoint for communication and returns a file descriptor
 * that can be used for subsequent socket operations, such as binding, connecting, or data transfer.
 *
 * @param[in] domain   Specifies the protocol family to be used for the socket. Common values include:
 *                      - `AF_INET`: IPv4 Internet protocols.
 *                      - `AF_INET6`: IPv6 Internet protocols.
 *                      - `AF_UNIX`: Local communication using UNIX domain sockets.
 * @param[in] type     Specifies the type of socket to be created. Common values include:
 *                      - `SOCK_STREAM`: Provides sequenced, reliable, two-way, connection-based byte streams.
 *                      - `SOCK_DGRAM`: Supports datagrams (connectionless, unreliable messages of fixed maximum length).
 *                      - `SOCK_RAW`: Provides raw network protocol access.
 * @param[in] protocol Specifies the specific protocol to be used. Typically set to `0` to use the default
 *                     protocol for the specified domain and type.
 *
 * @return sysret_t    Returns the socket file descriptor on success, or a negative error code on failure.
 *
 * @note The returned socket descriptor must be closed using `sys_close()` to release system resources.
 *
 * @warning Ensure the combination of `domain`, `type`, and `protocol` is valid. Invalid combinations
 *          may result in errors. For example, specifying `AF_INET` with `SOCK_DGRAM` is valid for UDP,
 *          but with `SOCK_STREAM` it is used for TCP.
 *
 * @see sys_bind(), sys_connect(), sys_accept(), sys_close()
 */
sysret_t sys_socket(int domain, int type, int protocol)
{
    int fd       = -1;
    int nonblock = 0;
    /* not support SOCK_CLOEXEC type */
    if (type & SOCK_CLOEXEC)
    {
        type &= ~SOCK_CLOEXEC;
    }
    if (type & SOCK_NONBLOCK)
    {
        nonblock  = 1;
        type     &= ~SOCK_NONBLOCK;
    }

    fd = socket(domain, type, protocol);
    if (fd < 0)
    {
        goto out;
    }
    if (nonblock)
    {
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }

out:
    return (fd < 0 ? GET_ERRNO() : fd);
}

/**
 * @brief Creates a pair of connected sockets.
 *
 * This system call creates two connected sockets that can be used for bidirectional communication
 * between processes or threads. The sockets are returned as file descriptors in the `fd` array.
 *
 * @param[in] domain   Specifies the protocol family to be used for the sockets. Common values include:
 *                      - `AF_UNIX`: Local communication using UNIX domain sockets.
 * @param[in] type     Specifies the type of socket to be created. Common values include:
 *                      - `SOCK_STREAM`: Provides sequenced, reliable, two-way, connection-based byte streams.
 *                      - `SOCK_DGRAM`: Supports datagrams (connectionless, unreliable messages of fixed maximum length).
 * @param[in] protocol Specifies the specific protocol to be used. Typically set to `0` to use the default
 *                     protocol for the specified domain and type.
 * @param[out] fd      An array of two integers where the connected socket descriptors will be stored.
 *                     After a successful call:
 *                      - `fd[0]`: The first socket descriptor.
 *                      - `fd[1]`: The second socket descriptor.
 *
 * @return sysret_t    Returns `0` on success, or a negative error code on failure.
 *
 * @note The sockets in the pair are connected and can be used for inter-process communication
 *       (IPC) or between threads in the same process.
 *
 * @warning Ensure the `domain`, `type`, and `protocol` combination is valid. This function is typically
 *          supported only for `AF_UNIX` domain.
 *
 * @see sys_socket(), sys_close()
 */
sysret_t sys_socketpair(int domain, int type, int protocol, int fd[2])
{
#ifdef RT_USING_SAL
    int ret = 0;
    int k_fd[2];

    if (!lwp_user_accessable((void *)fd, sizeof(int[2])))
    {
        return -EFAULT;
    }

    ret = socketpair(domain, type, protocol, k_fd);

    if (ret == 0)
    {
        lwp_put_to_user(fd, k_fd, sizeof(int[2]));
    }

    return ret;
#else
    return -ELIBACC;
#endif
}

/**
 * @brief Closes an open socket.
 *
 * This system call is used to close a previously opened socket. Once the socket is closed, it is no longer
 * valid for any further operations, such as sending, receiving, or other socket-related functions.
 *
 * @param[in] socket  The socket descriptor to be closed. This descriptor must be a valid socket that was
 *                    previously created with `sys_socket()` or related functions.
 *
 * @return sysret_t   Returns `0` on success, or a negative error code on failure.
 *
 * @note Once a socket is closed, any attempts to use the socket for communication will result in an error.
 *       The system will release any resources associated with the socket.
 *
 * @warning Make sure that no data is being transferred or pending on the socket before closing it.
 *          Closing an active socket might lead to data loss.
 *
 * @see sys_socket(), sys_shutdown()
 */
sysret_t sys_closesocket(int socket)
{
    return closesocket(socket);
}

struct musl_addrinfo
{
    int ai_flags;
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;

    struct musl_sockaddr *ai_addr;
    char *ai_canonname;

    struct musl_addrinfo *ai_next;
};

/**
 * @brief Resolves network addresses and service names into a list of address structures.
 *
 * This function provides a mechanism for resolving a host name and service name (or port number)
 * into a list of address structures suitable for use with socket-based communication. The function
 * can handle both IPv4 and IPv6 addresses and provides a flexible way to specify different types
 * of address and service resolution options.
 *
 * @param[in] nodename  The host name to be resolved. This can be a DNS name or an IP address in string format.
 *                      If `nodename` is `NULL`, the function will resolve the local host.
 * @param[in] servname  The service name (e.g., "http") or port number to be resolved. If `servname` is `NULL`,
 *                      the function will resolve the port number or address without any service association.
 * @param[in] hints     A pointer to a `struct musl_addrinfo` that provides hints for the address resolution.
 *                      It can be used to specify criteria such as the desired address family (IPv4 or IPv6),
 *                      socket type, protocol, and flags for resolution.
 * @param[out] res      A pointer to a `struct musl_addrinfo` that will be filled with the resolved address
 *                      information. The resulting linked list will contain one or more `struct musl_sockaddr`
 *                      structures, each representing a different address that can be used for communication.
 *
 * @return sysret_t     Returns `0` on success, indicating that the address resolution was successful.
 *                       On failure, returns a negative error code.
 *
 * @note The `res` parameter points to a linked list of resolved address structures. Each node in the list
 *       contains a different resolved address and can be used for socket connection purposes.
 *       It is important to free the memory allocated for the list after it is no longer needed, using `freeaddrinfo()`.
 *
 * @warning The `hints` structure allows you to specify various options for the resolution. However, incorrect
 *          hints may lead to unexpected or incorrect results. For example, if you request IPv6 addresses but
 *          the host only supports IPv4, the function may not return the expected results.
 *
 * @see freeaddrinfo(), sys_socket(), sys_connect(), sys_gethostbyname(), sys_gethostbyaddr()
 */
sysret_t sys_getaddrinfo(const char *nodename,
        const char *servname,
        const struct musl_addrinfo *hints,
        struct musl_addrinfo *res)
{
    int ret = -1;
    struct addrinfo *k_res = NULL;
    char *k_nodename = NULL;
    char *k_servname = NULL;
    struct addrinfo *k_hints = NULL;
    int len = 0;

    if (!lwp_user_accessable((void *)res, sizeof(*res)))
    {
        SET_ERRNO(EFAULT);
        goto exit;
    }
    if (nodename)
    {
        len = lwp_user_strlen(nodename);
        if (len <= 0)
        {
            SET_ERRNO(EFAULT);
            goto exit;
        }

        k_nodename = (char *)kmem_get(len + 1);
        if (!k_nodename)
        {
            SET_ERRNO(ENOMEM);
            goto exit;
        }

        if (lwp_get_from_user(k_nodename, (void *)nodename, len + 1) != len + 1)
        {
            SET_ERRNO(EFAULT);
            goto exit;
        }
    }
    if (servname)
    {
        len = lwp_user_strlen(servname);
        if (len <= 0)
        {
            SET_ERRNO(EFAULT);
            goto exit;
        }

        k_servname = (char *)kmem_get(len + 1);
        if (!k_servname)
        {
            SET_ERRNO(ENOMEM);
            goto exit;
        }

        if (lwp_get_from_user(k_servname, (void *)servname, len + 1) < 0)
        {
            SET_ERRNO(EFAULT);
            goto exit;
        }
    }

    if (hints)
    {
        if (!lwp_user_accessable((void *)hints, sizeof(*hints)))
        {
            SET_ERRNO(EFAULT);
            goto exit;
        }
        k_hints = (struct addrinfo *) rt_malloc(sizeof *hints);
        if (!k_hints)
        {
            SET_ERRNO(ENOMEM);
            goto exit;
        }

        rt_memset(k_hints, 0x0, sizeof(struct addrinfo));
        k_hints->ai_flags    = hints->ai_flags;
        k_hints->ai_family   = hints->ai_family;
        k_hints->ai_socktype = hints->ai_socktype;
        k_hints->ai_protocol = hints->ai_protocol;
        k_hints->ai_addrlen  = hints->ai_addrlen;
    }

    ret = sal_getaddrinfo(k_nodename, k_servname, k_hints, &k_res);
    if (ret == 0)
    {
        /* set sockaddr */
        sockaddr_tomusl(k_res->ai_addr, res->ai_addr);
        res->ai_addrlen = k_res->ai_addrlen;

        /* set up addrinfo */
        res->ai_family = k_res->ai_family;
        res->ai_flags  = k_res->ai_flags;
        res->ai_next = NULL;

        if (hints != NULL)
        {
            /* copy socktype & protocol from hints if specified */
            res->ai_socktype = hints->ai_socktype;
            res->ai_protocol = hints->ai_protocol;
        }

        sal_freeaddrinfo(k_res);
        k_res = NULL;
    }

exit:
    if (ret < 0)
    {
        ret = GET_ERRNO();
    }

    if (k_nodename)
    {
        kmem_put(k_nodename);
    }

    if (k_servname)
    {
        kmem_put(k_servname);
    }

    if (k_hints)
    {
        rt_free(k_hints);
    }

    return ret;
}

#define HOSTENT_BUFSZ   512

/**
 * @brief Resolves a host name to an address, with support for specifying the address family.
 *
 * This function performs a lookup of the specified host name, and resolves it to an address,
 * while allowing the caller to specify the desired address family (e.g., IPv4 or IPv6). It is
 * a reentrant version of `gethostbyname2`, meaning it is safe for use in multi-threaded applications.
 * The results are returned in a user-provided buffer to avoid memory allocation overhead.
 *
 * @param[in] name      The host name to be resolved. This can be a DNS name or an IP address in string format.
 * @param[in] af        The address family to use for the resolution. Common values are:
 *                      - `AF_INET` for IPv4 addresses.
 *                      - `AF_INET6` for IPv6 addresses.
 * @param[out] ret      A pointer to a `struct hostent` where the resolved host information will be stored.
 *                      This includes the host name, alias names, address type, and the address itself.
 * @param[in] buf       A buffer to store additional information required for the `struct hostent` structure.
 *                      This is needed to ensure the reentrant behavior and avoid memory allocation.
 * @param[in] buflen    The size of the buffer provided.
 * @param[out] result   A pointer to a `struct hostent*` that will point to the resolved host entry.
 *                      This will be set to the value of `ret` upon success.
 * @param[out] err      A pointer to an integer where error codes will be stored. If the function fails,
 *                      `err` will contain a non-zero value corresponding to the error.
 *
 * @return sysret_t     Returns `0` on success, indicating the resolution was successful.
 *                       On failure, returns a negative error code that indicates the failure reason.
 *
 * @note This function is reentrant and thread-safe, meaning it does not use static memory or global state.
 *       It relies on the buffers provided by the caller to store the resolved data.
 *
 * @see gethostbyname2(), sys_gethostbyname(), sys_socket(), sys_connect(), sys_getaddrinfo()
 */
sysret_t sys_gethostbyname2_r(const char *name, int af, struct hostent *ret,
        char *buf, size_t buflen,
        struct hostent **result, int *err)
{
    int ret_val = -1;
    int sal_ret = -1 , sal_err = -1;
    struct hostent sal_he, sal_tmp;
    struct hostent *sal_result = NULL;
    char *sal_buf = NULL;
    char *k_name  = NULL;
    int len = 0;

    if (!lwp_user_accessable((void *)err, sizeof(*err)))
    {
        SET_ERRNO(EFAULT);
        goto __exit;
    }

    if (!lwp_user_accessable((void *)result, sizeof(*result))
    || !lwp_user_accessable((void *)ret, sizeof(*ret))
    || !lwp_user_accessable((void *)buf, buflen))
    {
        /* not all arguments given */
        *err = EFAULT;
        SET_ERRNO(EFAULT);
        goto __exit;
    }

    len = lwp_user_strlen(name);
    if (len <= 0)
    {
        *err = EFAULT;
        SET_ERRNO(EFAULT);
        goto __exit;
    }

    k_name = (char *)kmem_get(len + 1);
    if (!k_name)
    {
        SET_ERRNO(ENOMEM);
        goto __exit;
    }

    if (lwp_get_from_user(k_name, (void *)name, len + 1) < 0)
    {
        SET_ERRNO(EFAULT);
        goto __exit;
    }

    *result = ret;
    sal_buf = (char *)malloc(HOSTENT_BUFSZ);
    if (sal_buf == NULL)
    {
        SET_ERRNO(ENOMEM);
        goto __exit;
    }

    /* get host by name in SAL */
    sal_ret = sal_gethostbyname_r(k_name, &sal_he, sal_buf, HOSTENT_BUFSZ, &sal_result, &sal_err);
    if (sal_ret == 0)
    {
        int index = 0, cnt = 0;
        char *ptr = buf;

        /* get counter */
        index = 0;
        while (sal_he.h_addr_list[index] != NULL)
        {
            index++;
        }
        cnt = index + 1;

        /* update user space hostent */
        lwp_put_to_user(buf, k_name, buflen - (ptr - buf));
        lwp_memcpy(&sal_tmp, &sal_he, sizeof(sal_he));
        sal_tmp.h_name = ptr;
        ptr += rt_strlen(k_name);

        sal_tmp.h_addr_list = (char**)ptr;
        ptr += cnt * sizeof(char *);

        index = 0;
        while (sal_he.h_addr_list[index] != NULL)
        {
            sal_tmp.h_addr_list[index] = ptr;
            lwp_memcpy(ptr, sal_he.h_addr_list[index], sal_he.h_length);

            ptr += sal_he.h_length;
            index++;
        }
        sal_tmp.h_addr_list[index] = NULL;
        lwp_put_to_user(ret, &sal_tmp, sizeof(sal_tmp));
        ret_val = 0;
    }
    else
    {
        SET_ERRNO(EINVAL);
    }

__exit:
    if (ret_val < 0)
    {
        ret_val = GET_ERRNO();
    }

    /* release buffer */
    if (sal_buf)
    {
        free(sal_buf);
    }
    if (k_name)
    {
        kmem_put(k_name);
    }

    return ret_val;
}

#endif
