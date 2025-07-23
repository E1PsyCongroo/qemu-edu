#include "proc.h"
#include "procfs.h"

#include <rthw.h>
#include <rtdbg.h>

#include <fcntl.h>
#include <errno.h>

#include <dfs_dentry.h>

// 从RT-Thread中断系统获取信息
extern struct rt_irq_desc irq_desc[];

// 获取系统支持的最大中断号
static int rt_interrupt_get_max_irq(void)
{
    // MAX_HANDLERS 在不同架构中定义不同，通常在interrupt.c中定义
    // 可以通过以下方式获取，或者直接使用架构相关的定义
#if defined(MAX_HANDLERS)
    return MAX_HANDLERS - 1;
#elif defined(IRQ_MAX_NR)
    return IRQ_MAX_NR - 1;
#else
    return 255; // 默认值，可根据实际平台调整
#endif
}

// 获取指定中断号的处理次数
static rt_uint32_t rt_interrupt_get_total(int irq)
{
    int max_irq = rt_interrupt_get_max_irq();
    
    if (irq < 0 || irq > max_irq)
        return 0;
    
    // rt_kprintf("Interrupt %d: %s %d", irq, irq_desc[irq].name, irq_desc[irq].counter);

    // 检查中断是否已安装处理程序
    if (irq_desc[irq].handler == RT_NULL)
        return 0;

#ifdef RT_USING_INTERRUPT_INFO
    return irq_desc[irq].counter;
#else
    // 如果没有启用中断统计，返回0或者1（表示有处理程序但无统计）
    return 0;
#endif
}

static void *seq_start(struct dfs_seq_file *seq, off_t *index)
{
    off_t i = *index;
    int max_irq = rt_interrupt_get_max_irq();
    
    // 查找下一个有效的中断号
    while (i <= max_irq)
    {
        rt_uint32_t count = rt_interrupt_get_total( i);
        if (count > 0)
        {
            return (void *)(i + 1); // 返回非空指针表示找到有效项
        }
        i++;
    }
    
    return NULL; // 没有更多项
}

static void seq_stop(struct dfs_seq_file *seq, void *data)
{
}

static void *seq_next(struct dfs_seq_file *seq, void *data, off_t *index)
{
    off_t i = *index + 1;
    int max_irq = rt_interrupt_get_max_irq();
    
    // 查找下一个有效的中断号
    while (i <= max_irq)
    {
        rt_uint32_t count = rt_interrupt_get_total(i);
        if (count > 0)
        {
            *index = i;
            return (void *)(i + 1); // 返回非空指针表示找到有效项
        }
        i++;
    }
    
    *index = i;
    return NULL; // 没有更多项
}

static int seq_show(struct dfs_seq_file *seq, void *data)
{
    off_t irq = seq->index;
    rt_uint32_t count = rt_interrupt_get_total(irq);
    
    if (count > 0)
    {
        dfs_seq_printf(seq, "%d:        %u\n", (int)irq, count);
    }
    
    return 0;
}

static const struct dfs_seq_ops seq_ops = {
    .start  = seq_start,
    .stop   = seq_stop,
    .next   = seq_next,
    .show   = seq_show,
};

rt_weak const struct dfs_seq_ops *interrupt_get_seq_ops(void)
{
    return &seq_ops;
}

static int proc_open(struct dfs_file *file)
{
    return dfs_seq_open(file, interrupt_get_seq_ops());
}

static int proc_close(struct dfs_file *file)
{
    return dfs_seq_release(file);
}

static ssize_t proc_write(struct dfs_file *file, const void *buf, size_t count, off_t *pos)
{
    rt_kprintf("permission denied!\n");
    return -EPERM;
}

static int proc_truncate(struct dfs_file *file, off_t offset)
{
    rt_kprintf("permission denied!\n");
    return -EPERM;
}

// 只读文件操作，不支持写入
static const struct dfs_file_ops file_ops = {
    .open   = proc_open,
    .read   = dfs_seq_read,
    .lseek  = dfs_seq_lseek,
    .close  = proc_close,
    .write  = proc_write,
    .truncate = proc_truncate,
};

int proc_interrupt_init(void)
{
    struct proc_dentry *dentry = proc_create_data("interrupts", 0444, NULL, &file_ops, NULL);
    proc_release(dentry);
    return 0;
}
INIT_ENV_EXPORT(proc_interrupt_init);