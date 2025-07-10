# DFS

DFS (Device File System) 是我们的 设备虚拟文件系统，官方提供了 v1 和 v2 两个版本，这里使用 v2 版本。

### 功能

- 提供了统一的，POSIX 兼容的接口，比如 read, write
- 支持多种不同的文件系统, 提供普通文件、设备文件和网络文件描述符的管理功能
- 支持多种类型的存储设备

### 架构

![DFS 架构](../img/dfs架构.png)

### 核心结构

这里列举一些核心结构方便理解

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