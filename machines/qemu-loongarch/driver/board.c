/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2021-01-30     lizhirui     first version
 */

#include <rthw.h>
#include <rtthread.h>
#include <rtdevice.h>

#include "board.h"
#include "timer.h"
#include "drv_uart.h"

#ifdef RT_USING_SMART
#include <mm_aspace.h>
#include <mm_page.h>

#include "mmu.h"
#include "lwp_arch.h"
#endif


#define IOREMAP_SIZE (1ul << 20)

#ifndef ARCH_REMAP_KERNEL
#define IOREMAP_VSTART 0x9000000010000000
#define IOREMAP_VEND (IOREMAP_VSTART + IOREMAP_SIZE)
#endif /* ARCH_REMAP_KERNEL */

#define KERNEL_PVADDR_OFFSET (-0x9000000000000000L)

#define KERNEL_PHY_MASK (0x000fffffffffffffUL)

#define KV2P(x) (((unsigned long)x) & KERNEL_PHY_MASK)

#ifdef RT_USING_SMART
rt_region_t init_page_region = {(rt_size_t)(RT_HW_PAGE_START), (rt_size_t)(RT_HW_PAGE_END)};

extern size_t MMUTable[];

struct mem_desc platform_mem_desc[] = {
    {KERNEL_VADDR_START, (rt_size_t)RT_HW_PAGE_END - 1, (rt_size_t)ARCH_MAP_FAILED, NORMAL_MEM},
};

#define NUM_MEM_DESC (sizeof(platform_mem_desc) / sizeof(platform_mem_desc[0]))
#endif



void rt_hw_board_init(void)
{
    // We must set pv offset before init.
    rt_kmem_pvoff_set(KERNEL_PVADDR_OFFSET);

#ifdef RT_USING_SMART
    /* init data structure */
    rt_hw_mmu_map_init(&rt_kernel_space, (void *)(IOREMAP_VEND - IOREMAP_SIZE), IOREMAP_SIZE, (rt_size_t *)MMUTable, PV_OFFSET);

    /* init page allocator */
    rt_page_init(init_page_region);

    /* setup region, and enable MMU */
    rt_hw_mmu_setup(&rt_kernel_space, platform_mem_desc, NUM_MEM_DESC);
#endif

#ifdef RT_USING_HEAP
    /* initialize memory system */
    rt_system_heap_init(RT_HW_HEAP_BEGIN, RT_HW_HEAP_END);
#endif

    rt_hw_interrupt_init();

    rt_hw_uart_init();

#ifdef RT_USING_CONSOLE
    /* set console device */
    rt_console_set_device(RT_CONSOLE_DEVICE_NAME);
#endif /* RT_USING_CONSOLE */

    rt_hw_timer_init();

    rt_tick_sethook(RT_NULL);

#ifdef RT_USING_COMPONENTS_INIT
    rt_components_board_init();
#endif

#ifdef RT_USING_HEAP
    rt_kprintf("heap: [0x%08x - 0x%08x]\n", (rt_ubase_t)RT_HW_HEAP_BEGIN, (rt_ubase_t)RT_HW_HEAP_END);
#endif /* RT_USING_HEAP */
}

void rt_hw_cpu_reset(void)
{
    while (1);
}

MSH_CMD_EXPORT_ALIAS(rt_hw_cpu_reset, reboot, reset machine);

