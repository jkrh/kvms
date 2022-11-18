include $(BASE_DIR)/stdlib/stdlib.mk

LIBNAME := libstdlib.a
C_SOURCES := $(STDLIB_SRCS) time.c qsort.c bsearch.c \
	strchr.c math.c lz4cpy.c lz4decode.c lz4check.c \
	mempcpy.c
AS_SOURCES := memcmp.S memcpy.S memset.S strchr.S \
	strcmp.S strlen.S strncmp.S strnlen.S
CFLAGS += -DAARCH64

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)
