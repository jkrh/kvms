$(info PRODUCT:       $(PRODUCT))

OUTDIR = $(OBJDIR)/$(PLATFORM)/$(CHIPSET)/$(PRODUCT)
SUBDIRS = $(CHIPSET) $(CHIPSET)/$(PRODUCT)

all: createdir check dirs
check:
	@[ "${PRODUCT}" ] && echo -n "" || ( echo "PRODUCT is not set"; exit 1 )

dirs: $(SUBDIRS) | $(OBJDIR)
	@for DIR in $(SUBDIRS); do \
		$(MAKE) $(SUBMAKEFLAGS) ENABLE_TESTS=false -C$${DIR}; \
	done

createdir:
	@mkdir -p $(OUTDIR)

clean:
	@for DIR in $(SUBDIRS); do \
		$(MAKE) $(SUBUMAKEFLAGS) -C$${DIR} clean; \
	done
	@rm -rf $(OBJDIR)

.PHONY: all clean $(SUBDIRS)
