# FAL

FAL(Flash Abstraction Layer) 是 RT-Thread 提供的一套 Flash 设备抽象层组件，它为 Flash 设备提供了统一的接口。

下面是 fal 的一些核心结构

```c
struct fal_flash_dev 
{
    char name[FAL_DEV_NAME_MAX];  /* Flash 设备名称 */
    
    /* Flash 地址信息 */
    long addr;            /* 起始地址 */
    size_t len;           /* 总容量 */
    size_t blk_size;      /* 块大小 */
    
    /* 设备操作函数集 */
    struct {
        int (*init)(void);
        int (*read)(long offset, uint8_t *buf, size_t size);
        int (*write)(long offset, const uint8_t *buf, size_t size);
        int (*erase)(long offset, size_t size);
    } ops;
    
    /* 写入粒度，单位：bit */
    rt_size_t write_gran;
};

struct fal_partition
{
    rt_uint32_t magic_word;         /* 分区标识符 */
    
    char name[FAL_DEV_NAME_MAX];    /* 分区名称 */
    char flash_name[FAL_DEV_NAME_MAX]; /* 所属 Flash 设备名称 */
    
    long offset;                    /* 在 Flash 设备上的偏移地址 */
    rt_size_t len;                  /* 分区大小 */
    
    rt_uint32_t reserved;           /* 保留字段 */
};
```


