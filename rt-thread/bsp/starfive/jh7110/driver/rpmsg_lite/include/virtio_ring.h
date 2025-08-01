/*-
 * Copyright Rusty Russell IBM Corporation 2007.
 * Copyright 2019,2022 NXP
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef VIRTIO_RING_H
#define VIRTIO_RING_H

/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT 1U
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE 2U
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT 4U

/* The Host uses this in used->flags to advise the Guest: don't kick me
 * when you add a buffer.  It's unreliable, so it's simply an
 * optimization.  Guest will still kick if it's out of buffers. */
#define VRING_USED_F_NO_NOTIFY 1U
/* The Guest uses this in avail->flags to advise the Host: don't
 * interrupt me when you consume a buffer.  It's unreliable, so it's
 * simply an optimization.  */
#define VRING_AVAIL_F_NO_INTERRUPT 1U

/* VirtIO ring descriptors: 16 bytes.
 * These can chain together via "next". */
struct vring_desc
{
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too. */
    uint16_t next;
};

struct vring_avail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[0];
};

/* uint32_t is used here for ids for padding reasons. */
struct vring_used_elem
{
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was written to. */
    uint32_t len;
};

struct vring_used
{
    uint16_t flags;
    uint16_t idx;
    struct vring_used_elem ring[0];
};

struct vring
{
    uint32_t num;

    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
};

/* The standard layout for the ring is a continuous chunk of memory which
 * looks like this.  We assume num is a power of 2.
 *
 * struct vring {
 *      # The actual descriptors (16 bytes each)
 *      struct vring_desc desc[num];
 *
 *      # A ring of available descriptor heads with free-running index.
 *      __u16 avail_flags;
 *      __u16 avail_idx;
 *      __u16 available[num];
 *      __u16 used_event_idx;
 *
 *      # Padding to the next align boundary.
 *      char pad[];
 *
 *      # A ring of used descriptor heads with free-running index.
 *      __u16 used_flags;
 *      __u16 used_idx;
 *      struct vring_used_elem used[num];
 *      __u16 avail_event_idx;
 * };
 *
 * NOTE: for VirtIO PCI, align is 4096.
 */

/*
 * We publish the used event index at the end of the available ring, and vice
 * versa. They are at the end for backwards compatibility.
 */
#define vring_used_event(vr)  ((vr)->avail->ring[(vr)->num])
#define vring_avail_event(vr) ((vr)->used->ring[(vr)->num].id)

static inline int32_t vring_size(uint32_t num, uint32_t align)
{
    uint32_t size;

    size = num * sizeof(struct vring_desc);
    size += sizeof(struct vring_avail) + (num * sizeof(uint16_t)) + sizeof(uint16_t);
    size = (size + align - 1UL) & ~(align - 1UL);
    size += sizeof(struct vring_used) + (num * sizeof(struct vring_used_elem)) + sizeof(uint16_t);
    return ((int32_t)size);
}

static inline void vring_init(struct vring *vr, uint32_t num, uint8_t *p, uint32_t align)
{
    vr->num   = num;
    vr->desc  = (struct vring_desc *)(void *)p;
    vr->avail = (struct vring_avail *)(void *)(p + num * sizeof(struct vring_desc));
    vr->used  = (struct vring_used *)(((uintptr_t)&vr->avail->ring[num] + align - 1UL) & ~(align - 1UL));
}

/*
 * The following is used with VIRTIO_RING_F_EVENT_IDX.
 *
 * Assuming a given event_idx value from the other size, if we have
 * just incremented index from old to new_idx, should we trigger an
 * event?
 */
static inline int32_t vring_need_event(uint16_t event_idx, uint16_t new_idx, uint16_t old)
{
    /* coco begin validated: This function does not need to be tested because it is not used in rpmsg_lite
     * implementation (only called from unused part of vq_ring_must_notify_host() ). */
    if ((uint16_t)(new_idx - event_idx - 1U) < (uint16_t)(new_idx - old))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
/* coco end */
#endif /* VIRTIO_RING_H */
