/* SPDX-License-Identifier: GPL-2.0-only */
#include "linuxmacros.h"
.text
.arch   armv8-a+crypto

.global	__store_simd
.type	__store_simd,%function
.align 2
__store_simd:
	fpsimd_save x0, 1
	ret

.global	__restore_simd
.type	__restore_simd,%function
.align 2
__restore_simd:
	fpsimd_restore x0, 1
	ret
