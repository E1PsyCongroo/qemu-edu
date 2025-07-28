/**
 * Copyright (C) 2013 Guangzhou Tronlong Electronic Technology Co., Ltd. - www.tronlong.com
 *
 * @file main.c
 *
 * @brief Example application main file.
 * This application receive data from linux through rpmsg
 * and send back to linux through rpmsg.
 *
 * @author Tronlong <support@tronlong.com>
 *
 * @version V1.0
 *
 * @date 2023-8-10
 **/
#include <rtthread.h>
#include <rtdevice.h>
#include <riscv_io.h>
#include "rpmsg_lite.h"
#include "rpmsg_queue.h"
#include "rpmsg_ns.h"

/* CPU0 as master and CPU3 as remote. */
#define MASTER_ID   ((uint32_t)1)
#define REMOTE_ID_3 ((uint32_t)4)

/* define endpoint id for test */
#define RPMSG_RTT_REMOTE_TEST3_EPT_ID 0x4004U
#define RPMSG_RTT_REMOTE_TEST_EPT3_NAME "rpmsg_chrdev"

#define RPMSG_LINUX_MEM_BASE 0x6e410000
#define RPMSG_LINUX_MEM_END  0x6e7fffff
#define RPMSG_LINUX_MEM_SIZE (2UL * RL_VRING_OVERHEAD)

//#define RL_PLATFORM_SET_LINK_ID(mid, rid) ((mid << 16) | rid)

struct rpmsg_block_t
{
    uint32_t len;
    uint8_t buffer[496 - 4];
};

struct rpmsg_info_t
{
    struct rpmsg_lite_instance *instance;
    struct rpmsg_lite_endpoint *ept;
    uint32_t cb_sta;    /* callback status flags */
    void *private;
};

static void rpmsg_share_mem_check(void)
{
    if ((RPMSG_LINUX_MEM_BASE + RPMSG_LINUX_MEM_SIZE) > RPMSG_LINUX_MEM_END)
    {
        rt_kprintf("share memory size error!\n");
        while (1)
        {
            ;
        }
    }
}

void rpmsg_ns_cb(uint32_t new_ept, const char *new_ept_name, uint32_t flags, void *user_data)
{
    uint32_t cpu_id;
    char ept_name[RL_NS_NAME_SIZE];

    cpu_id = __raw_hartid();
    strncpy(ept_name, new_ept_name, RL_NS_NAME_SIZE);
    rt_kprintf("rpmsg remote: name service callback cpu_id-%ld\n", cpu_id);
    rt_kprintf("rpmsg remote: new_ept-0x%lx name-%s\n", new_ept, ept_name);
}

static rpmsg_queue_handle g_remote_queue;

static void rpmsg_linux_test_thread_entry(void *parameter)
{
    struct rpmsg_info_t *info = (struct rpmsg_info_t *)parameter;
    uint32_t master_ept_id;
    char *rx_msg = (char *)rt_malloc(RL_BUFFER_PAYLOAD_SIZE);
    uint32_t r_len;

    while (1) {
        rpmsg_queue_recv(info->instance, g_remote_queue,
			(uint32_t *)&master_ept_id, rx_msg, RL_BUFFER_PAYLOAD_SIZE, &r_len, RL_BLOCK);
        rpmsg_lite_send(info->instance, info->ept, master_ept_id, rx_msg, r_len, RL_BLOCK);
    }

    return;
}

static void rpmsg_linux_test(void)
{
    int j;
    uint32_t master_id, remote_id;
    struct rpmsg_info_t *info;
    struct rpmsg_block_t *block;
    uint32_t master_ept_id;
    uint32_t ept_flags;
    void *ns_cb_data;
    rt_thread_t tid;

    rpmsg_share_mem_check();
    master_id = MASTER_ID;
    //remote_id = HAL_CPU_TOPOLOGY_GetCurrentCpuId();
    remote_id = __raw_hartid();
    rt_kprintf("rpmsg remote: remote core cpu_id-%ld\n", remote_id);
    rt_kprintf("rpmsg remote: shmem_base-0x%lx shmem_end-0x%lx\n", RPMSG_LINUX_MEM_BASE, RPMSG_LINUX_MEM_END);

    info = (void *)rt_malloc(sizeof(struct rpmsg_info_t));
    if (info == NULL)
    {
        rt_kprintf("info malloc error!\n");
        while (1)
        {
            ;
        }
    }
    info->private = (void *)rt_malloc(sizeof(struct rpmsg_block_t));
    if (info->private == NULL)
    {
        rt_kprintf("info malloc error!\n");
        while (1)
        {
            ;
        }
    }

    info->instance = rpmsg_lite_remote_init((void *)RPMSG_LINUX_MEM_BASE,
		//RL_PLATFORM_SET_LINK_ID(master_id, remote_id)
		0, RL_NO_FLAGS); /* set link id to 0 */
    rpmsg_lite_wait_for_link_up(info->instance, 0);
    rt_kprintf("rpmsg remote: link up! link_id-0x%lx\n", info->instance->link_id);
    rpmsg_ns_bind(info->instance, rpmsg_ns_cb, &ns_cb_data);

    g_remote_queue  = rpmsg_queue_create(info->instance);
    info->ept = rpmsg_lite_create_ept(info->instance, RPMSG_RTT_REMOTE_TEST3_EPT_ID,
		rpmsg_queue_rx_cb, g_remote_queue);
    ept_flags = RL_NS_CREATE;
    rpmsg_ns_announce(info->instance, info->ept, RPMSG_RTT_REMOTE_TEST_EPT3_NAME, ept_flags);

#ifdef RT_USING_HEAP
    tid = rt_thread_create("rpmsg_linux_test", rpmsg_linux_test_thread_entry, info,
                           4096, RT_MAIN_THREAD_PRIORITY - 1, 20);
    RT_ASSERT(tid != RT_NULL);

    rt_thread_startup(tid);
#endif
}

int rpmsg_test(void)
{
    rt_uint32_t cpu_id;

    cpu_id = __raw_hartid();
    rt_kprintf("Hello Starfive RT-Thread! CPU_ID(%d)\n", cpu_id);

    rt_kprintf("rpmsg linux test: receive data from linux then send back\n");
    rpmsg_linux_test();

    return RT_EOK;
}
