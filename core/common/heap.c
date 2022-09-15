// SPDX-License-Identifier: GPL-2.0-only
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>

#include "helpers.h"
#include "spinlock.h"
#include "heap.h"

uint8_t hyp_malloc_pool[MALLOC_POOL_SIZE] ALIGN(PAGE_SIZE) WEAK_SYM;
static spinlock_t malloc_lock = 0;
static void *__heap;
static size_t __heap_sz;

/* title: malloc () / free () - pair according to K&R 2, p.185 */
typedef long Align;

union header {
	struct {
		union header *ptr;	/* Pointer to circular successor */
		unsigned size;		/* Size of the block */
	} s;
	Align x;
};

typedef union header header;
static header base;			/* Start header */
static header *freep = NULL;		/* Current entry point in free list */

void kr_free(void *ap);
void __kr_free(void *ap);

int set_heap(void *h, size_t sz)
{
	if (!h || !sz)
		return -EINVAL;

#ifdef MINIMUM_MALLOC_SIZE
	if (sz < MINIMUM_MALLOC_SIZE)
		return -EINVAL;
#endif
	if (sz % 8)
		return -EINVAL;

	__heap = h;
	__heap_sz = sz;
	memset(h, 0, sz);

	return 0;
}

uint8_t *get_static_buffer(size_t size)
{
	static size_t buf_index;
	uint8_t *bufp = NULL;

	size = ROUND_UP(size, sizeof(double));
	if (size > __heap_sz)
		return NULL;

	if ((buf_index + size) >= __heap_sz)
		return NULL;

	bufp = (uint8_t *)__heap + buf_index;
	buf_index += size;
	*bufp = 0;

	return bufp;
}

static header *morespace(unsigned nu)
{
	header *up;
	uint8_t *cp;

#ifdef MINIMUM_MALLOC_SIZE
	if (nu < MINIMUM_MALLOC_SIZE)
		nu = MINIMUM_MALLOC_SIZE / sizeof(header) + 1;
#endif
	cp = get_static_buffer(nu * sizeof(header));
	if (!cp)
		return NULL;
	up = (header *)cp;
	up->s.size = nu;
	__kr_free((void *)(up + 1));

	return freep;
}

void *__kr_malloc(size_t nbytes)
{
	header *p, *prevp;
	unsigned nunits;

	nunits = (nbytes + sizeof(header) - 1) / sizeof(header) + 1;
	prevp = freep;
	if (prevp == NULL) {
		base.s.ptr = freep = prevp = &base;
		base.s.size = 0;
	}
	for (p = prevp->s.ptr;; prevp = p, p = p->s.ptr) {
		if (p->s.size >= nunits) {
			if (p->s.size == nunits) {
				prevp->s.ptr = p->s.ptr;
			} else {
				p->s.size -= nunits;
				p += p->s.size;
				p->s.size = nunits;
			}
			freep = prevp;
			return (void *)(p + 1);
		}
		if (p == freep) {
			p = morespace(nunits);
			if (p == NULL)
				return NULL;
		}
	}
}

void *kr_malloc(size_t nbytes)
{
	void *res;

	spin_lock(&malloc_lock);
	res = __kr_malloc(nbytes);
	spin_unlock(&malloc_lock);

	return res;
}

void __kr_free(void *ap)
{
	header *bp, *p;

	bp = (header *)ap - 1;

	for (p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
		if (p >= p->s.ptr && (bp > p || bp < p->s.ptr))
			break;

	if (bp + bp->s.size == p->s.ptr) {
		bp->s.size += p->s.ptr->s.size;
		bp->s.ptr = p->s.ptr->s.ptr;
	} else {
		bp->s.ptr = p->s.ptr;
	}
	if (p + p->s.size == bp) {
		p->s.size += bp->s.size;
		p->s.ptr = bp->s.ptr;
	} else {
		p->s.ptr = bp;
	}
	freep = p;
}

void kr_free(void *ap)
{
	spin_lock(&malloc_lock);
	__kr_free(ap);
	spin_unlock(&malloc_lock);
}

WEAK_ALIAS(kr_malloc, malloc);
WEAK_ALIAS(kr_free, free);
