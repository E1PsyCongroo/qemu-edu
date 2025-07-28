/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * Copyright (c) 2015 Xilinx, Inc.
 * Copyright (c) 2016 Freescale Semiconductor, Inc.
 * Copyright 2016-2023 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**************************************************************************
 * FILE NAME
 *
 *       rpmsg_env_rtthread.c
 *
 *
 * DESCRIPTION
 *
 *       This file is RT-thread RTOS Implementation of env layer for rpmsg-lite.
 *
 *
 **************************************************************************/

#include "rpmsg_compiler.h"
#include "rpmsg_env.h"
#include "rpmsg_lite.h"
//#include <zephyr.h>
#include <io.h>
//#include <rtthread.h>
#include "rpmsg_platform.h"
#include "virtqueue.h"
#include <rtthread.h>
#include <rtdevice.h>
#include "virtqueue.h"

#include <stdlib.h>
#include <string.h>


#if defined(RL_USE_ENVIRONMENT_CONTEXT) && (RL_USE_ENVIRONMENT_CONTEXT == 1)
#error "This RPMsg-Lite port requires RL_USE_ENVIRONMENT_CONTEXT set to 0"
#endif

/* RL_ENV_MAX_MUTEX_COUNT is an arbitrary count greater than 'count'
   if the inital count is 1, this function behaves as a mutex
   if it is greater than 1, it acts as a "resource allocator" with
   the maximum of 'count' resources available.
   Currently, only the first use-case is applicable/applied in RPMsg-Lite.
 */
#define RL_ENV_MAX_MUTEX_COUNT (10)
/* Max supported ISR counts */
#define ISR_COUNT (32U)
/*!
 * Structure to keep track of registered ISR's.
 */
struct isr_info
{
    void *data;
};
static struct isr_info isr_table[ISR_COUNT];

/*!
 * env_in_isr
 *
 * @returns - true, if currently in ISR
 *
 */
static int32_t env_in_isr(void)
{
}

/*!
 * env_wait_for_link_up
 *
 * Wait until the link_state parameter of the rpmsg_lite_instance is set.
 * Utilize events to avoid busy loop implementation.
 *
 */
 extern int ipi_init; 

uint32_t env_vring_init(struct vring *vr, unsigned int num, void *p,
			      unsigned long align)

{
	unsigned long addr;
	uint32_t offset;

	vr->num   = num;
	vr->desc  = (struct vring_desc *)(void *)p;

	addr = (unsigned long) (p + num * sizeof(struct vring_desc) + align - 1UL);
	addr &= ~(align - 1UL);
	vr->avail = (void *)addr;
	addr = (unsigned long)&vr->avail->ring[num];
	addr += (align - 1UL);
	addr &= ~(align - 1UL);
	vr->used  = (struct vring_used *)addr;
	addr = (unsigned long)&vr->used->ring[num];
	addr += (align - 1UL);
	addr &= ~(align - 1UL);

	return addr - (unsigned long) vr->desc;
}

uint32_t env_wait_for_link_up(volatile uint32_t *link_state, uint32_t link_id, uint32_t timeout_ms)
{

    if (*link_state != 1U)
    {
	while (1) {
		if (ipi_init) {
			*link_state = 1;
			return 1;
		}
		rt_schedule();
	}
    }
    else
    {
        return 1U;
    }
}

/*!
 * env_tx_callback
 *
 * Set event to notify task waiting in env_wait_for_link_up().
 *
 */
void env_tx_callback(uint32_t link_id)
{

}

/*!
 * env_init
 *
 * Initializes OS/BM environment.
 *
 */
int32_t env_init(void)
{
    int32_t retval;

    retval = platform_init();

    return retval;
}

/*!
 * env_deinit
 *
 * Uninitializes OS/BM environment.
 *
 * @returns - execution status
 */
int32_t env_deinit(void)
{
    return 0;
}

/*!
 * env_allocate_memory - implementation
 *
 * @param size
 */
void *env_allocate_memory(uint32_t size)
{
    return (rt_malloc(size));
}

/*!
 * env_free_memory - implementation
 *
 * @param ptr
 */
void env_free_memory(void *ptr)
{
    if (ptr != ((void *)0))
    {
        rt_free(ptr);
    }
}

/*!
 *
 * env_memset - implementation
 *
 * @param ptr
 * @param value
 * @param size
 */
void env_memset(void *ptr, int32_t value, uint32_t size)
{
    (void)rt_memset(ptr, value, size);
}

/*!
 *
 * env_memcpy - implementation
 *
 * @param dst
 * @param src
 * @param len
 */
void env_memcpy(void *dst, void const *src, uint32_t len)
{
    (void)rt_memcpy(dst, src, len);
}

/*!
 *
 * env_strcmp - implementation
 *
 * @param dst
 * @param src
 */

int32_t env_strcmp(const char *dst, const char *src)
{
    return (rt_strcmp(dst, src));
}

/*!
 *
 * env_strncpy - implementation
 *
 * @param dest
 * @param src
 * @param len
 */
void env_strncpy(char *dest, const char *src, uint32_t len)
{
    (void)rt_strncpy(dest, src, len);
}

/*!
 *
 * env_strncmp - implementation
 *
 * @param dest
 * @param src
 * @param len
 */
int32_t env_strncmp(char *dest, const char *src, uint32_t len)
{
    return (rt_strncmp(dest, src, len));
}

/*!
 *
 * env_mb - implementation
 *
 */
void env_mb(void)
{
    mb();
}

/*!
 * env_rmb - implementation
 */
void env_rmb(void)
{
   rmb();
}

/*!
 * env_wmb - implementation
 */
void env_wmb(void)
{
    wmb();
}

/*!
 * env_map_vatopa - implementation
 *
 * @param address
 */
uint32_t env_map_vatopa(void *addr)
{
  return ((uintptr_t)(char *)addr);
}

/**
  * platform_patova
  *
  * Dummy implementation
  *
  */
void *env_map_patova(uint32_t addr)
{
   return ((void *)(uint64_t)addr);
}

/*!
 * env_create_mutex
 *
 * Creates a mutex with the given initial count.
 *
 */
#if defined(RL_USE_STATIC_API) && (RL_USE_STATIC_API == 1)
int32_t env_create_mutex(void **lock, int32_t count, void *context)
#else
int32_t env_create_mutex(void **lock, int32_t count)
#endif
{
    rt_mutex_t mutex;
    char mutex_name[16] = "rpmsg";
    int ret;

    if (count > RL_ENV_MAX_MUTEX_COUNT)
    {
        return -1;
    }
    mutex_name[5] = count + '0';

    mutex  = rt_mutex_create(mutex_name, 0);

    if (!mutex)
    	return -1;

    *lock = (void *)mutex;
    return 0;
}

/*!
 * env_delete_mutex
 *
 * Deletes the given lock
 *
 */
void env_delete_mutex(void *lock)
{ /* todo */
#if 0
    k_sem_reset(lock);
#if !(defined(RL_USE_STATIC_API) && (RL_USE_STATIC_API == 1))
    env_free_memory(lock);
#endif
#endif
}

/*!
 * env_lock_mutex
 *
 * Tries to acquire the lock, if lock is not available then call to
 * this function will suspend.
 */
void env_lock_mutex(void *lock)
{ /* todo */
#if 0
    if (env_in_isr() == 0)
    {
        k_sem_take((struct k_sem *)lock, K_FOREVER);
    }
#endif
}

/*!
 * env_unlock_mutex
 *
 * Releases the given lock.
 */
void env_unlock_mutex(void *lock)
{
#if 0
    if (env_in_isr() == 0)
    {
        k_sem_give((struct k_sem *)lock);
    }
#endif
}

/*!
 * env_create_sync_lock
 *
 * Creates a synchronization lock primitive. It is used
 * when signal has to be sent from the interrupt context to main
 * thread context.
 */
#if defined(RL_USE_STATIC_API) && (RL_USE_STATIC_API == 1)
int32_t env_create_sync_lock(void **lock, int32_t state, void *context)
{
    return env_create_mutex(lock, state, context); /* state=1 .. initially free */
}
#else
int32_t env_create_sync_lock(void **lock, int32_t state)
{
    return env_create_mutex(lock, state); /* state=1 .. initially free */
}
#endif

/*!
 * env_delete_sync_lock
 *
 * Deletes the given lock
 *
 */
void env_delete_sync_lock(void *lock)
{
    if (lock != ((void *)0))
    {
        env_delete_mutex(lock);
    }
}

/*!
 * env_acquire_sync_lock
 *
 * Tries to acquire the lock, if lock is not available then call to
 * this function waits for lock to become available.
 */
void env_acquire_sync_lock(void *lock)
{
    if (lock != ((void *)0))
    {
        env_lock_mutex(lock);
    }
}

/*!
 * env_release_sync_lock
 *
 * Releases the given lock.
 */
void env_release_sync_lock(void *lock)
{
    if (lock != ((void *)0))
    {
        env_unlock_mutex(lock);
    }
}

/*!
 * env_sleep_msec
 *
 * Suspends the calling thread for given time , in msecs.
 */
void env_sleep_msec(uint32_t num_msec)
{
    rt_thread_delay(rt_tick_from_millisecond(num_msec));
}

/*!
 * env_register_isr
 *
 * Registers interrupt handler data for the given interrupt vector.
 *
 * @param vector_id - virtual interrupt vector number
 * @param data      - interrupt handler data (virtqueue)
 */
void env_register_isr(uint32_t vector_id, void *data)
{
    //RL_ASSERT(vector_id < ISR_COUNT);
    if (vector_id < ISR_COUNT)
    	isr_table[vector_id].data = data;
}

/*!
 * env_unregister_isr
 *
 * Unregisters interrupt handler data for the given interrupt vector.
 *
 * @param vector_id - virtual interrupt vector number
 */
void env_unregister_isr(uint32_t vector_id)
{
    //RL_ASSERT(vector_id < ISR_COUNT);
    if (vector_id < ISR_COUNT)
    {
        isr_table[vector_id].data = ((void *)0);
    }
}

/*!
 * env_enable_interrupt
 *
 * Enables the given interrupt
 *
 * @param vector_id   - virtual interrupt vector number
 */

void env_enable_interrupt(uint32_t vector_id)
{
    //(void)platform_interrupt_enable(vector_id);
}

/*!
 * env_disable_interrupt
 *
 * Disables the given interrupt
 *
 * @param vector_id   - virtual interrupt vector number
 */

void env_disable_interrupt(uint32_t vector_id)
{
    //(void)platform_interrupt_disable(vector_id);
}

/*!
 * env_map_memory
 *
 * Enables memory mapping for given memory region.
 *
 * @param pa   - physical address of memory
 * @param va   - logical address of memory
 * @param size - memory size
 * param flags - flags for cache/uncached  and access type
 */

void env_map_memory(uint32_t pa, uint32_t va, uint32_t size, uint32_t flags)
{
    //platform_map_mem_region(va, pa, size, flags);
}

/*!
 * env_disable_cache
 *
 * Disables system caches.
 *
 */

void env_disable_cache(void)
{
    //platform_cache_all_flush_invalidate();
    //platform_cache_disable();
}

/*========================================================= */
/* Util data / functions  */

void env_isr(uint32_t vector)
{
    struct isr_info *info;
    //RL_ASSERT(vector < ISR_COUNT);
    if (vector < ISR_COUNT)
    {
        info = &isr_table[vector];
        virtqueue_notification((struct virtqueue *)info->data);
    }
}

/*
 * env_create_queue
 *
 * Creates a message queue.
 *
 * @param queue -  pointer to created queue
 * @param length -  maximum number of elements in the queue
 * @param element_size - queue element size in bytes
 * @param queue_static_storage - pointer to queue static storage buffer
 * @param queue_static_context - pointer to queue static context
 *
 * @return - status of function execution
 */
#if defined(RL_USE_STATIC_API) && (RL_USE_STATIC_API == 1)
int32_t env_create_queue(void **queue,
                         int32_t length,
                         int32_t element_size,
                         uint8_t *queue_static_storage,
                         rpmsg_static_queue_ctxt *queue_static_context)
#else
int32_t env_create_queue(void **queue, int32_t length, int32_t element_size)
#endif
{
    rt_mq_t queue_ptr;

    queue_ptr =  rt_mq_create("rpmsg-lite-queue", element_size, length, RT_IPC_FLAG_FIFO);

    if (queue_ptr == ((void *)0))
    {
        return -1;
    }

    *queue = (void *)queue_ptr;
    return 0;
}

/*!
 * env_delete_queue
 *
 * Deletes the message queue.
 *
 * @param queue - queue to delete
 */

void env_delete_queue(void *queue)
{
    rt_mq_delete((rt_mq_t)queue);
}

/*!
 * env_put_queue
 *
 * Put an element in a queue.
 *
 * @param queue - queue to put element in
 * @param msg - pointer to the message to be put into the queue
 * @param timeout_ms - timeout in ms
 *
 * @return - status of function execution
 */

int32_t env_put_queue(void *queue, void *msg, uintptr_t timeout_ms)
{
#if 0
    if (env_in_isr() != 0)
    {
        timeout_ms = 0; /* force timeout == 0 when in ISR */
    }
#endif
    rt_mq_t mq = (void *)queue;

    if (0 == rt_mq_send((rt_mq_t)queue, msg, mq->msg_size))
    {
        return 1;
    }

    return 0;
}

/*!
 * env_get_queue
 *
 * Get an element out of a queue.
 *
 * @param queue - queue to get element from
 * @param msg - pointer to a memory to save the message
 * @param timeout_ms - timeout in ms
 *
 * @return - status of function execution
 */

int32_t env_get_queue(void *queue, void *msg, uintptr_t timeout_ms)
{
#if 0
    if (env_in_isr() != 0)
    {
        timeout_ms = 0; /* force timeout == 0 when in ISR */
    }
#endif
    rt_mq_t mq = (void *)queue;

    if (RL_BLOCK == timeout_ms) {
	    if (rt_mq_recv((rt_mq_t)queue, msg, mq->msg_size, 0x1000000))
	    	return 1;
    } else {
        if (rt_mq_recv((rt_mq_t)queue, msg, mq->msg_size, rt_tick_from_millisecond(timeout_ms)))
		 return 1;
    }
    return 0;
}

/*!
 * env_get_current_queue_size
 *
 * Get current queue size.
 *
 * @param queue - queue pointer
 *
 * @return - Number of queued items in the queue
 */
#if 0
int32_t env_get_current_queue_size(void *queue)
{
    //return k_msgq_num_used_get((struct k_msgq *)queue);
}
#endif
