/*
 * Copyright (c) 2013-2016, ARM Limited and Contributors. All rights reserved.
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

HYP_BASE = 0xE0000000;
HYP_VECTOR_OFFSET = 0x20000;
HYP_SIZE = 0x3000000;
HYP_LIMIT = (HYP_BASE + HYP_SIZE);

ENTRY(hyp_entrypoint)

MEMORY {
    RAM (rwx): ORIGIN = HYP_BASE, LENGTH = HYP_LIMIT - HYP_BASE
}

SECTIONS
{
    . = HYP_BASE;
    ASSERT(. == ALIGN(4096),
           "HYP_BASE address is not aligned on a page boundary.")

    .text . : {
        __RO_START__ = .;
        __TEXT_START__ = .;
        *hyp_entrypoint.o(.text*)
        *(.text*)
        . = HYP_VECTOR_OFFSET;
        *(.vectors*)
        . = NEXT(4096);
        __TEXT_END__ = .;
     } >RAM

    .rodata . : {
        __RODATA_START__ = .;
        *(.rodata*)

        /* Ensure 8-byte alignment for descriptors and ensure inclusion */
        . = ALIGN(8);
        __PARSER_LIB_DESCS_START__ = .;
        KEEP(*(.img_parser_lib_descs))
        __PARSER_LIB_DESCS_END__ = .;

        . = NEXT(4096);
        __RODATA_END__ = .;
        __RO_END__ = .;
    } >RAM

    /*
     * Define a linker symbol to mark start of the RW memory area for this
     * image.
     */
    . = ALIGN(4096);
    __RW_START__ = . ;

    .data . : ALIGN(16) {
        __DATA_RAM_START__ = .;
        *(.data*)
        __DATA_RAM_END__ = .;
    } >RAM

    stacks . (NOLOAD) : {
        __STACKS_START__ = .;
        *(tzfw_normal_stacks)
        __STACKS_END__ = .;
    } >RAM

   /*
    * The .bss section gets initialised to 0 at runtime.
    * Its base address must be 16-byte aligned.
    */
   .bss (NOLOAD) : ALIGN(16) {
        __BSS_START__ = .;
        *(.bss*)
        *(COMMON)
       __BSS_END__ = .;
    } >RAM
    __BSS_SIZE__ = SIZEOF(.bss);

    /*
     * The xlat_table section is for full, aligned page tables (4K).
     * Removing them from .bss avoids forcing 4K alignment on
     * the .bss section and eliminates the unecessary zero init
     */
    xlat_table (NOLOAD) : ALIGN(4096) {
        __XLAT_START__ = .;
        *(xlat_table)
        __XLAT_END__ = .;
    } >RAM
    __XLAT_SIZE__ = SIZEOF(xlat_table);

    __BL1_RAM_START__ = ADDR(.data);
    __BL1_RAM_END__ = .;

    ASSERT(. <= HYP_LIMIT, "HYP's RW section has exceeded its limit.")
}
