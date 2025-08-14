# MM组件

MM组件用于和LWP协作，实现用户程序内存管理。MM组件实现了页的分配功能。MM组件的`aspace`用于直接对用户的虚拟内存空间做管理，底层由具体的体系结构实现，`aspace`提供了一个抽象层，每一个lwp都有一个对应的`aspace`对象。mm主要实现了以下功能：

- 对于有对操作系统内核虚拟内存保护的体系结构，映射MMIO区域

- 以页面为单位的内存分配和管理

- 虚拟内存层面的`fork`，即申请一份新的页表，复制自己，组织新的页表结构

- 虚拟内存页的`map`和`unmap`，用于lwp加载ELF文件的时候做不同权限的映射以及用户程序请求系统调用的时候

- 处理产生的缺页异常，实现写时复制等功能

mm的核心功能就是对`aspace`的实现。

```c
extern struct rt_aspace rt_kernel_space;

typedef struct rt_aspace
{
    void *start;
    rt_size_t size;

    void *page_table;
    mm_spinlock_t pgtbl_lock;

    struct _aspace_tree tree;
    struct rt_mutex bst_lock;

    struct rt_mem_obj *private_object;

#ifdef ARCH_USING_ASID
    rt_uint64_t asid;
#endif /* ARCH_USING_ASID */

} *rt_aspace_t;

typedef struct rt_mem_obj
{
    void (*hint_free)(rt_mm_va_hint_t hint);
    void (*on_page_fault)(struct rt_varea *varea, struct rt_aspace_fault_msg *msg);

    /* do pre open bushiness like inc a ref */
    void (*on_varea_open)(struct rt_varea *varea);
    /* do post close bushiness like def a ref */
    void (*on_varea_close)(struct rt_varea *varea);

    /* do preparation for address space modification of varea */
    rt_err_t (*on_varea_shrink)(struct rt_varea *varea, void *new_vaddr, rt_size_t size);
    /* do preparation for address space modification of varea */
    rt_err_t (*on_varea_expand)(struct rt_varea *varea, void *new_vaddr, rt_size_t size);
    /**
     * this is like an on_varea_open() to `subset`, and an on_varea_shrink() to `existed`
     * while resource can migrate from `existed` to `subset` at the same time
     */
    rt_err_t (*on_varea_split)(struct rt_varea *existed, void *unmap_start,
                               rt_size_t unmap_len, struct rt_varea *subset);
    /**
     * this is like a on_varea_expand() to `merge_to` and on_varea_close() to `merge_from`
     * while resource can migrate from `merge_from` to `merge_to` at the same time
     */
    rt_err_t (*on_varea_merge)(struct rt_varea *merge_to, struct rt_varea *merge_from);

    /* dynamic mem_obj API */
    void (*page_read)(struct rt_varea *varea, struct rt_aspace_io_msg *msg);
    void (*page_write)(struct rt_varea *varea, struct rt_aspace_io_msg *msg);

    const char *(*get_name)(rt_varea_t varea);

    void *(*on_varea_mremap)(struct rt_varea *varea, rt_size_t new_size, int flags, void *new_address);
} *rt_mem_obj_t;
```

`aspace`记录基本的内存空间的起始、大小，和一个体系结构实现的页表、一个用于快速查找页映射和组织`varea`的数据结构。`mem_obj`则是具体操作的实现，例如如何处理缺页异常，这一部分由LWP组件注册并实现。`varea`用来记录和操作一个具体的内存映射，做一次`map`就是向`aspace`里面新增一个`varea`。

`rt_mem_obj`是一个接口，里面提供了页异常处理、页面读写、区域大小改变处理函数等具体接口。

`aspace`提供了以下的方法

```c
rt_err_t rt_aspace_duplicate_locked(rt_aspace_t src, rt_aspace_t dst);
rt_err_t rt_aspace_fork(rt_aspace_t *psrc, rt_aspace_t *pdst);
rt_err_t rt_aspace_compare(rt_aspace_t src, rt_aspace_t dst);
int rt_aspace_map(rt_aspace_t aspace, void **addr, rt_size_t length, rt_size_t attr, mm_flag_t flags, rt_mem_obj_t mem_obj, rt_size_t offset);
int rt_aspace_unmap(rt_aspace_t aspace, void *addr);
```

- 地址空间创建和销毁

- 内存映射和解除内存映射、内存重映射

- 复制地址空间

- 虚拟地址和内核的物理地址转换

同时，`aspace`提供了对数据结构的锁机制，来应对操作系统存在的并发。