# DFS

DFS (Device File System) 是我们的 **设备虚拟文件系统**，提供了 v1 和 v2 两个版本，这里使用 v2 版本。

### 功能

- 提供了统一的，POSIX 兼容的接口，如 open, read 等。
- 支持多种不同的文件系统, 提供普通文件、设备文件和网络文件描述符的管理功能。
- 支持多种类型的存储设备。

### 架构

![DFS 架构](../img/dfs架构.png)

#### POSIX 接口层

POSIX 实现了标准的 POSIX 文件操作接口，如 open(), read(), write(), close() 等，为应用程序提供了符合 POSIX 标准的文件系统访问接口。，目的是更加轻松的移植  Linux/Unix 程序。

#### 虚拟系统层

虚拟系统层 提供了注册、挂载、卸载多种特定文件系统（如 FatFS, RomFS, DevFS 等）的能力, 实现了统一的文件系统接口抽象，虚拟节点和目录项的管理。

#### 设备抽象层

设备抽象层将物理设备（如SD卡、SPI Flash、Nand Flash）抽象为文件系统可访问的设备。例如，FAT文件系统要求存储设备为块设备类型。

不同的文件系统类型独立于存储设备驱动实现，因此只需将底层存储设备的驱动接口与文件系统对接，即可正常使用文件系统功能。

### 核心结构

这里列举一些核心结构设计

文件操作结构

```c
struct dfs_file_ops
{
    int (*open)     (struct dfs_file *fd);
    int (*close)    (struct dfs_file *fd);
    int (*ioctl)    (struct dfs_file *fd, int cmd, void *args);
    ssize_t (*read)     (struct dfs_file *fd, void *buf, size_t count);
    ssize_t (*write)    (struct dfs_file *fd, const void *buf, size_t count);
    int (*flush)    (struct dfs_file *fd);
    off_t (*lseek)    (struct dfs_file *fd, off_t offset);
    int (*getdents) (struct dfs_file *fd, struct dirent *dirp, uint32_t count);

    int (*poll)     (struct dfs_file *fd, struct rt_pollreq *req);
};
```

虚拟节点

```c
struct dfs_vnode
{
    uint16_t type;               /* Type (regular or socket) */

    char *path;                  /* Name (below mount point) */
    char *fullpath;              /* Full path is hash key */
    int ref_count;               /* Descriptor reference count */
    rt_list_t list;              /* The node of vnode hash table */

    struct dfs_filesystem *fs;
    const struct dfs_file_ops *fops;
    uint32_t flags;              /* self flags, is dir etc.. */

    size_t   size;               /* Size in bytes */
    void *data;                  /* Specific file system data */
};
```

文件描述符

```c
struct dfs_file
{
    uint16_t magic;              /* file descriptor magic number */
    uint32_t flags;              /* Descriptor flags */
    int ref_count;               /* Descriptor reference count */
    off_t    pos;                /* Current file position */
    struct dfs_vnode *vnode;     /* file node struct */
    void *data;                  /* Specific fd data */
};
```

### 使用

通过 ```dfs_init``` 完成 DFS 组件的初始化，通过 ```dfs_register``` 来初始化对应的文件系统类型。然后 ```dfs_mkfs``` 在块设备上面创建指定的文件系统，使用 ```dfs_mount/dfs_unmount``` 挂载/卸载文件系统。