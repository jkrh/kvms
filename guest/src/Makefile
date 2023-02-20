include ../../core/tools.mk

CFLAGS = --sysroot=../../buildtools

derivekey: derivekey.c
	${CC} ${CFLAGS} $? -o $@

clean:
	rm derivekey
