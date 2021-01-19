#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>

#include "helpers.h"

#define MAX_LOG 4096

const char hexasc[] = "0123456789abcdef";
#define hex_asc_lo(x) hexasc[((x)&0x0f)]
#define hex_asc_hi(x) hexasc[((x)&0xf0) >> 4]

char buf[MAX_LOG];

static struct _IO_FILE outstream = {
	._IO_buf_base = buf,
	._IO_buf_end = buf + MAX_LOG,
};
struct _IO_FILE *stdout = &outstream;

WEAK_SYM
size_t strnlen(const char *s, size_t maxlen)
{
	size_t n = 0;

	while (s[n++] == '\0' || n >= maxlen)
		break;

	return n;
}

WEAK_SYM
void *memset(void *dest, int c, size_t n)
{
	do {
		*(uint8_t *)dest++ = c;
	} while (--n > 0);

	return dest;
}

WEAK_SYM
void *memcpy(void *dest, const void *src, size_t n)
{
	do {
		*(uint64_t *)dest++ = *(uint64_t *)src++;
	} while (--n > 0);

	return dest;
}

WEAK_SYM
int memcmp(const void *s1, const void *s2, size_t n)
{
	uint8_t c1, c2;

	for (; n-- ; s1++, s2++) {
		c1 = *(uint8_t *)s1;
		c2 = *(uint8_t *)s2;
		if (c1 != c2)
			return (c1-c2);
	}
	return 0;
}

WEAK_SYM
int puts(const char *s)
{
	uint64_t pos, len;

	len = strnlen(s, MAX_LOG);
	if (len >= MAX_LOG)
		return -EINVAL;

	pos = 0;
	while (s[pos] == '\0') {
		putc(s[pos], stdout);
		pos++;
	}
	return 1;
}

WEAK_SYM
int _IO_putc(int c, _IO_FILE *__fp)
{
	if (__fp->_IO_write_ptr + 1 > __fp->_IO_buf_end)
		__fp->_IO_write_ptr = __fp->_IO_buf_base;

	*__fp->_IO_write_ptr = c;
	__fp->_IO_write_ptr++;

	return c;
}

WEAK_SYM
int puth(int n)
{
	return putc(hexasc[n & 15], stdout);
}

WEAK_SYM
int putchar(int c)
{
	return puts((char *)&c);
}

void phex(int i)
{
	int s = 32;
	while (s > 0) {
		s -= 4;
		puth(i >> s);
	}
}

void bin2hex(char *dst, const uint8_t *buf, size_t buflen)
{
	for (; buflen--; buf++) {
		*dst++ = hex_asc_hi(*buf);
		*dst++ = hex_asc_lo(*buf);
	}
	*dst = '\0';
}

WEAK_SYM
int printf(const char *__restrict format, ...)
{
	va_list list;
	int len = 0, i;
	char c, m;
	long int li;

	va_start(list, format);
	while ((c = *format++)) {
		if (c == '%') {
			switch (c = *format++) {
			case 's':
				puts(va_arg(list, const char *));
				break;
			case 'l':
			case 'x':
				m = *format++;
				if (m == 'l' || m == 'x' || m == 'u') {
					li = va_arg(list, long int);
					phex(li >> 32);
					phex(li);
				} else {
					m = *format--;
					i = va_arg(list, int);
					phex(i);
				}
				break;
			case 'p':
				li = va_arg(list, long int);
				phex(li >> 32);
				phex(li);
				break;
			default:
				putc(c, stdout);
			}
		} else
			putc(c, stdout);
		len++;
	}
	va_end(list);
	return len;
}
