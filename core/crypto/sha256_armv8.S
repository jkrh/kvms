/* SPDX-License-Identifier: GPL-2.0-only */
.text
.arch armv8-a+crypto

.global	sha256_armv8
.type sha256_armv8, %function
.align 2

sha256_armv8:
	str q8, [sp, #-48]!
	str q9, [sp, #16]
	str q10, [sp, #32]

	mov x3, x0
	ld1 {v0.4s}, [x3], #16
	ld1 {v1.4s}, [x3]

	ld1 {v2.16b-v5.16b}, [x1], #64
	rev32 v2.16b, v2.16b
	rev32 v3.16b, v3.16b
	rev32 v4.16b, v4.16b
	rev32 v5.16b, v5.16b

	mov v6.16b, v0.16b
	mov v7.16b, v1.16b
	mov v8.16b, v6.16b

	ld1 {v9.4s-v12.4s}, [x2], #64
	ld1 {v13.4s-v16.4s}, [x2], #64
	ld1 {v17.4s-v20.4s}, [x2], #64
	ld1 {v21.4s-v24.4s}, [x2], #64

	add v25.4s, v2.4s, v9.4s
	add v26.4s, v3.4s, v10.4s
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v2.4s, v3.4s

	add v25.4s, v4.4s, v11.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v3.4s, v4.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	add v26.4s, v5.4s, v12.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v4.4s, v5.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	add v25.4s, v2.4s, v13.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v5.4s, v2.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	add v26.4s, v3.4s, v14.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v2.4s, v3.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	add v25.4s, v4.4s, v15.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v3.4s, v4.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	add v26.4s, v5.4s, v16.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v4.4s, v5.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	add v25.4s, v2.4s, v17.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v5.4s, v2.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	add v26.4s, v3.4s, v18.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v2.4s, v3.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	add v25.4s, v4.4s, v19.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v3.4s, v4.4s
	sha256su1 v2.4s, v4.4s, v5.4s

	add v26.4s, v5.4s, v20.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su0 v4.4s, v5.4s
	sha256su1 v3.4s, v5.4s, v2.4s

	add v25.4s, v2.4s, v21.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	sha256su0 v5.4s, v2.4s
	sha256su1 v4.4s, v2.4s, v3.4s

	add v26.4s, v3.4s, v22.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	sha256su1 v5.4s, v3.4s, v4.4s

	add v25.4s, v4.4s, v23.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s

	add v26.4s, v5.4s, v24.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v25.4s
	sha256h2 q7, q8, v25.4s
	mov v8.16b, v6.16b
	sha256h q6, q7, v26.4s
	sha256h2 q7, q8, v26.4s
	add v1.4s, v1.4s, v7.4s
	add v0.4s, v0.4s, v6.4s

	st1 {v0.4s,v1.4s}, [x0]
	ldr q10, [sp, #32]
	ldr q9, [sp, #16]
	ldr q8, [sp], #48
	ret
