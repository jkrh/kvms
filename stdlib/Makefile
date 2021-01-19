include $(BASE_DIR)/stdlib/stdlib.mk

LIBNAME := libstdlib.a
C_SOURCES := $(STDLIB_SRCS) time.c
CFLAGS += -DAARCH64

include $(BASE_DIR)/core/common.mk

all: $(OBJDIR)/$(LIBNAME)
