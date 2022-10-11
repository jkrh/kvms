# SPDX-License-Identifier: GPL-2.0-only

INCLUDES := -I$(CORE_DIR)

LINK := -T ld.out
LDFLAGS := -static $(LINK)

start.o: start.S
	$(CC) $(ASFLAGS) -o $@ -c $<

ic_loader.o: ic_loader.c
	$(CC) $(CFLAGS) -FPIC -fno-sanitize=all -o $@ -c $<

ic_loader: start.o ic_loader.o
	$(LD) $(LDFLAGS) -o ic_loader.elf -static start.o ic_loader.o
	$(OBJCOPY) -O binary ic_loader.elf ic_loader

clean:
	rm -f start.o ic_loader.o ic_loader.elf ic_loader
