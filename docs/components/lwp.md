# lwp

lwp 是我们的 **轻量级进程管理系统** , 它作为一个核心组件,为 系统提供了用户态的进程支持,同时提供进程间通信,资源隔离,系统调用等功能。

## 功能特性

- **进程管理**：创建、销毁、调度用户态进程
- **内存隔离**：每个进程拥有独立的虚拟地址空间
- **系统调用**：POSIX 兼容的系统调用接口
- **进程间通信**：管道、消息队列、共享内存、信号等
- **动态加载**：支持 ELF 格式的可执行文件和动态链接库
- **作业控制**：进程组、会话管理、终端控制
- **信号处理**：完整的 POSIX 信号机制
- **资源管理**：文件描述符、定时器、内存等资源的生命周期管理

## 架构设计

### 整体架构

```mermaid
graph TB
    A[用户应用] --> B[POSIX API]
    B --> C[系统调用接口]
    C --> D[LWP 核心]
    
    D --> E[进程管理]
    D --> F[内存管理]
    D --> G[信号处理]
    D --> H[IPC通信]
    D --> I[ELF加载器]
    D --> J[PID管理]
    
    E --> K[RT-Thread 内核]
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K
    
    K --> L[硬件抽象层]
```

### 进程流程

```mermaid
sequenceDiagram
    participant 用户应用
    participant RT-Thread内核
    participant lwp核心
    participant lwp_pid
    participant lwp_elf
    participant lwp_user_mm
    
    用户应用->>RT-Thread内核: 创建进程请求
    RT-Thread内核->>lwp核心: exec/lwp_execve()
    lwp核心->>lwp_pid: lwp_create()/lwp_pid_get()
    lwp_pid-->>lwp核心: 返回进程ID
    
    lwp核心->>lwp_user_mm: lwp_user_space_init()
    lwp_user_mm-->>lwp核心: 初始化进程地址空间
    
    lwp核心->>lwp_elf: lwp_load()
    lwp_elf-->>lwp核心: 加载ELF可执行文件
    
    lwp核心->>RT-Thread内核: 创建进程主线程
    RT-Thread内核->>lwp核心: 线程创建完成
    
    lwp核心->>RT-Thread内核: rt_thread_startup()
    RT-Thread内核-->>lwp核心: 线程启动成功
    
    lwp核心-->>用户应用: 返回进程ID
    
    Note over 用户应用,lwp_user_mm: 进程运行
    
    用户应用->>RT-Thread内核: 系统调用请求
    RT-Thread内核->>lwp核心: 进入系统调用处理
    lwp核心-->>用户应用: 返回系统调用结果
    
    用户应用->>RT-Thread内核: 进程退出请求
    RT-Thread内核->>lwp核心: lwp_terminate()
    lwp核心->>lwp_pid: lwp_pid_put()
    lwp_pid-->>lwp核心: 释放进程ID
    
    lwp核心->>lwp_user_mm: lwp_unmap_user_space()
    lwp_user_mm-->>lwp核心: 释放进程地址空间
    
    lwp核心-->>RT-Thread内核: 进程退出完成
    RT-Thread内核-->>用户应用: 进程终止
```

## 核心架构

### lwp 核心结构体

```c
// lwp.h
struct rt_lwp
{
#ifdef ARCH_MM_MMU
    size_t end_heap;
    size_t brk; // end of heap show to user
    rt_aspace_t aspace;
#else
#ifdef ARCH_MM_MPU
    struct rt_mpu_info mpu_info;
#endif /* ARCH_MM_MPU */
#endif /* ARCH_MM_MMU */

#ifdef RT_USING_SMP
    int bind_cpu;
#endif

    uint8_t lwp_type;
    uint8_t reserv[3];

    /* flags */
    unsigned int terminated:1;
    unsigned int background:1;
    unsigned int term_ctrlterm:1;  /* have control terminal? */
    unsigned int did_exec:1;       /* Whether exec has been performed */
    unsigned int jobctl_stopped:1; /* job control: current proc is stopped */
    unsigned int wait_reap_stp:1;  /* job control: has wait event for parent */
    unsigned int sig_protected:1;  /* signal: protected proc cannot be killed or stopped */

    struct rt_lwp *parent;          /* parent process */
    struct rt_lwp *first_child;     /* first child process */
    struct rt_lwp *sibling;         /* sibling(child) process */

    struct rt_wqueue waitpid_waiters;
    lwp_status_t lwp_status;

    void *text_entry;
    uint32_t text_size;
    void *data_entry;
    uint32_t data_size;

    rt_atomic_t ref;
    void *args;
    uint32_t args_length;
    pid_t pid;
    pid_t sid;                      /* session ID */
    pid_t pgid;                     /* process group ID */
    struct rt_processgroup *pgrp;
    rt_list_t pgrp_node;            /* process group node */
    rt_list_t t_grp;                /* thread group */
    rt_list_t timer;                /* POSIX timer object binding to a process */

    struct dfs_fdtable fdt;
    char cmd[RT_NAME_MAX];
    char *exe_file;                 /* process file path */

    /* POSIX signal */
    struct lwp_signal signal;

    mode_t umask;

    struct lwp_avl_struct *object_root;
    struct rt_mutex object_mutex;
    struct rt_user_context user_ctx;

    struct rt_wqueue wait_queue; /* for console */
    struct tty_struct *tty; /* NULL if no tty */

    struct lwp_avl_struct *address_search_head; /* for addressed object fast search */
    char working_directory[DFS_PATH_MAX];

    int debug;
    rt_uint32_t bak_first_inst; /* backup of first instruction */

    struct rt_mutex lwp_lock;

    rt_slist_t signalfd_notify_head;

#ifdef LWP_ENABLE_ASID
    uint64_t generation;
    unsigned int asid;
#endif
    struct rusage rt_rusage;

#ifdef RT_USING_VDSO
    void *vdso_vbase;
#endif
};
```

### 系统调用

系统调用(syscall) 模块提供用户空间与内核空间的接口，兼容 POSIX 标准，用来提供多种操作的上层api,并且具有完善的权限检查和安全控制。

### 内存管理

内存管理模块 是 **mm** 组件的用户空间内存管理上层封装和拓展，负责用户进程的虚拟内存管理，内存隔离和保护。提供了内存映射，页面权限管理，堆栈管理，内存锁等内存操作

### 进程ID管理

PID 管理模块 负责 PID 的分配和管理,包括 PID 的分配,回收，查找等功能。

### 信号处理

信号系统提供了异步事件通知机制，兼容 POSIX 型号标准，负责信号处理的接口和实现,包括信号的发送,接收,处理，信号队列管理，实时信号支持等功能.

### 进程间通信

IPC 模块提供多种进程间通信机制，支持数据交换和同步,包括管道,消息队列，套接字通信,共享内存等功能.

### 动态加载

提供了 elf 格式的解析和加载功能,支持动态链接库,可以用来加载和执行用户程序.

### 作业控制

作业控制系统提供了进程组和绘画管理功能，支持前后台进程控制


