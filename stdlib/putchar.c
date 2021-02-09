/*
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
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

#include <stdio.h>
#include <host_platform.h>
#include <bits/types/struct_FILE.h>
#include <spinlock.h>

#include "commondefines.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

static char __logbuf[PAGE_SIZE * 4];

static struct _IO_FILE outstream = {
	._IO_buf_base = __logbuf,
	._IO_buf_end = __logbuf + sizeof(__logbuf),
	._IO_write_ptr = __logbuf,
	._IO_read_ptr = __logbuf,
};

struct _IO_FILE *stdout = &outstream;
struct _IO_FILE *stderr = &outstream;

int _IO_putc(int c, struct _IO_FILE *__fp);

#ifndef DEBUG
static uint64_t print_lock;

static void wraparound_ptrs(struct _IO_FILE *__fp)
{
	if (__fp->_IO_read_ptr + 1 > __fp->_IO_buf_end)
		__fp->_IO_read_ptr = __fp->_IO_buf_base;
	if (__fp->_IO_write_ptr + 1 > __fp->_IO_buf_end)
		__fp->_IO_write_ptr = __fp->_IO_buf_base;
}

int _IO_putc(int c, struct _IO_FILE *__fp)
{
	spin_lock(&print_lock);
	*__fp->_IO_write_ptr = c;
	__fp->_IO_write_ptr++;

	/* drop the oldest char if we've filled the buffer */
	if (__fp->_IO_read_ptr == __fp->_IO_write_ptr)
		__fp->_IO_read_ptr++;

	wraparound_ptrs(__fp);
	spin_unlock(&print_lock);

	return 0;
}

int __getchar(void)
{
	struct _IO_FILE *__fp = stdout;
	int chr = -1;

	spin_lock(&print_lock);
	if (__fp->_IO_read_ptr == __fp->_IO_write_ptr)
		goto out_unlock;

	chr = *__fp->_IO_read_ptr;
	__fp->_IO_read_ptr++;

	wraparound_ptrs(__fp);

out_unlock:
	spin_unlock(&print_lock);

	return chr;
}
#endif

int putchar(int c)
{
	return _IO_putc(c, stdout);
}

int putc(int c, FILE *stream)
{
	return _IO_putc(c, stream);
}
