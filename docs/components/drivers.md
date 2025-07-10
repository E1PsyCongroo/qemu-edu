# Drivers

Drivers 是一个驱动框架组件，它为上层应用提供了标准化的设备访问接口。

Drivers 通过 IO 设备管理框架，提供了标准的API。同时采取面向对象设计来实现更加清晰的结构。

系统采用了 rt_device 的结构来管理设备

```c
struct rt_device
{
    struct rt_object          parent;        /* kernel object base class */
    enum rt_device_class_type type;          /* device type */
    rt_uint16_t               flag;          /* device parameter */
    rt_uint16_t               open_flag;     /* device open flag */
    rt_uint8_t                ref_count;     /* number of times the device was cited */
    rt_uint8_t                device_id;     /* device ID,0 - 255 */

    /* data transceiving callback function */
    rt_err_t (*rx_indicate)(rt_device_t dev, rt_size_t size);
    rt_err_t (*tx_complete)(rt_device_t dev, void *buffer);

    const struct rt_device_ops *ops;    /* device operate methods */

    /* device's private data */
    void *user_data;
};
typedef struct rt_device *rt_device_t;
```

在 components/drivers 下面有诸多目录，每一个目录都是一种设备的驱动的具体实现。
