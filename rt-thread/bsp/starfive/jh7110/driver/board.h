/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2021-01-30     lizhirui     first version
 */

#ifndef BOARD_H__
#define BOARD_H__

#include <rtconfig.h>

extern unsigned int __bss_start;
extern unsigned int __bss_end;

#ifndef RT_USING_SMART
#define KERNEL_VADDR_START 0x0
#endif

#define HEAP_PHY_START 0x6f000000

#define RT_HW_HEAP_BEGIN ((void *)HEAP_PHY_START)
#define RT_HW_HEAP_END   ((void *)(RT_HW_HEAP_BEGIN + 16 * 1024 * 1024))
#if 0 /* todo */
#define RT_HW_PAGE_START RT_HW_HEAP_END
#define RT_HW_PAGE_END   ((void *)(KERNEL_VADDR_START + 8 * 1024 * 1024))
#endif

void rt_hw_board_init(void);
void rt_init_user_mem(struct rt_thread *thread, const char *name,
                      unsigned long *entry);

#endif
