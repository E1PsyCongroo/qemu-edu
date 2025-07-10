# LIBC 组件

LIBC组件实现了大量常用的POSIX标准下的C标准库函数，例如`printf`、`open`、`errno`等函数，在内核线程中，可以直接调用这些函数。这些函数的实现和GLIBC等C库的实现不同，LIBC中实现的函数无需通过系统调用接口层，就可以直接使用内核提供的所有功能，它会直接调用内核运行环境中提供的函数，运行高效。且所有的函数声明都与C标准兼容，在编写程序的时候，可以直接引用编译器提供的标准头文件，这极大地方便了内核程序的编写。同时，LIBC组件也提供了对C++运行环境的支持，例如异常支持。

libc组件实现了以下标准库支持：

## Delay

```c
unsigned int sleep(unsigned int seconds);
void msleep(unsigned int msecs);
void ssleep(unsigned int seconds);
void mdelay(unsigned long msecs);
void udelay(unsigned long usecs);
void ndelay(unsigned long nsecs);
```

`sleep`和`delay`一系列的函数最终会调用RT-Thread内核提供的`rt_hw_us_delay`函数进行休眠。

## IO

和标准的LIBC一样，RT-Thread使用文件描述符记录任务打开的文件，任务通过文件描述符操作打开的文件。

IO库提供了以下功能：

### 异步IO

```c
int aio_cancel(int fd, struct aiocb *cb);
int aio_error (const struct aiocb *cb);

int aio_fsync(int op, struct aiocb *cb);

int aio_read(struct aiocb *cb);
ssize_t  aio_return(struct aiocb *cb);
int aio_suspend(const struct aiocb *const list[], int nent,
             const struct timespec *timeout);
int aio_write(struct aiocb *cb);

int lio_listio(int mode, struct aiocb * const list[], int nent,
            struct sigevent *sig);
```

异步IO提供了异步读写、挂起、返回等功能。

### SignalFD

signalfd 和 Linux 一样，提供了一种将信号转换为文件描述符的机制。通过它，应用程序能够以操作文件描述符的方式来处理信号，例如使用 select、poll 或 epoll 进行多路复用，从而避免了传统信号处理函数带来的异步执行和重入问题。

### TimerFD

timerfd 和 Linux 一样，提供了一种将定时器转换为文件描述符的机制。通过它，应用程序可以像操作普通文件描述符一样操作定时器，例如使用 select、poll 或 epoll 进行多路复用，从而将定时器事件和其他 I/O 事件统一处理。

## IPC

IPC用于任务之间的通信，IPC实现了消息队列和同步信号量。

```c
struct mq_attr
{
    long mq_flags;      /* Message queue flags. */
    long mq_maxmsg;     /* Maximum number of messages. */
    long mq_msgsize;    /* Maximum message size. */
    long mq_curmsgs;    /* Number of messages currently queued. */
};

int     mq_close(mqd_t mqdes);
int     mq_getattr(mqd_t mqdes, struct mq_attr *mqstat);
int     mq_notify(mqd_t mqdes, const struct sigevent *notification);
mqd_t   mq_open(const char *name, int oflag, ...);
ssize_t mq_receive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned *msg_prio);
int     mq_send(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned msg_prio);
int     mq_setattr(mqd_t                 mqdes,
                   const struct mq_attr *mqstat,
                   struct mq_attr       *omqstat);
ssize_t mq_timedreceive(mqd_t                  mqdes,
                        char                  *msg_ptr,
                        size_t                 msg_len,
                        unsigned              *msg_prio,
                        const struct timespec *abs_timeout);
int     mq_timedsend(mqd_t                  mqdes,
                     const char            *msg_ptr,
                     size_t                 msg_len,
                     unsigned               msg_prio,
                     const struct timespec *abs_timeout);

int     mq_unlink(const char *name);
```

消息队列支持打开、删除、通知、发送等功能，发送的时候可以设置一个超时时间，如果消息队列在指定时间内一直是满的，则会返回一个错误。在编写代码的时候，可以直接使用Linux系统编程的方式。

```c
struct posix_sem
{
    /* reference count and unlinked */
    rt_uint16_t refcount;
    rt_uint8_t unlinked;
    rt_uint8_t unamed;

    /* RT-Thread semaphore */
    rt_sem_t sem;

    /* next posix semaphore */
    struct posix_sem* next;
};
typedef struct posix_sem sem_t;

int sem_close(sem_t *sem);
int sem_destroy(sem_t *sem);
int sem_getvalue(sem_t *sem, int *sval);
int sem_init(sem_t *sem, int pshared, unsigned int value);
sem_t *sem_open(const char *name, int oflag, ...);
int sem_post(sem_t *sem);
int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout);
int sem_trywait(sem_t *sem);
int sem_unlink(const char *name);
int sem_wait(sem_t *sem);
```

同步量提供了传统的创建、删除、PV操作等等，同时提供了一个超时wait、尝试wait以及一个特殊的获取同步量值的函数。

## signal

signal库提供了一系列的对信号的操作。

```c
int sigprocmask (int how, const sigset_t *set, sigset_t *oset);
int sigpending  (sigset_t *set);
int sigsuspend (const sigset_t *set);
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
```

signal库的底层调用了RT-Thread内核提供的信号操作。

```c
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    rt_sighandler_t old = RT_NULL;

    if (!sig_valid(signum)) return -RT_ERROR;

    if (act)
        old = rt_signal_install(signum, act->sa_handler);
    else
    {
        old = rt_signal_install(signum, RT_NULL);
        rt_signal_install(signum, old);
    }

    if (oldact)
        oldact->sa_handler = old;

    return 0;
}
```

例如`rt_signal_install`函数，是RT-Thread内核设置信号的函数。

## pthreads

pthreads提供了posix标准下一系列`pthread`的函数，例如对`mutex`互斥锁的操作，对`cond`条件变量的操作。

```c
/* pthread mutex interface */
int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_getprioceiling(const pthread_mutex_t *mutex, int *prioceiling);
int pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int prioceiling, int *old_ceiling);
```

```c
int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_broadcast(pthread_cond_t *cond);
int pthread_cond_signal(pthread_cond_t *cond);
```

## C++运行时环境

C++运行时环境实现了`new`和`delete`等C++运行必须的函数，底层仍然调用了RT-Thread的C接口，例如`new`和`delete`只是对`rt_malloc`和`rt_free`的包装。

```cpp
void *operator new(size_t size)
{
    return rt_malloc(size);
}

void *operator new[](size_t size)
{
    return rt_malloc(size);
}

void operator delete(void *ptr)
{
    rt_free(ptr);
}

void operator delete[](void *ptr)
{
    return rt_free(ptr);
}
```

C++运行时环境还重写了例如`std::mutex`一类的，原本需要操作系统支持的C++函数和类，让它们可以在RT-Thread运行环境下正常工作。
