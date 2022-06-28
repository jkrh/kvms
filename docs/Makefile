# SPDX-License-Identifier: GPL-2.0-only

DOC_DIR := $(BASE_DIR)/docs
DOC_CONF := $(DOC_DIR)/doxygen.config
DOC_TARGET := $(DOC_DIR)/refman.pdf

$(DOC_TARGET):
	$(DOXYGEN) $(DOC_CONF) $(TOPDIR)/doxygen.out
	$(MAKE) -s -C $(DOC_DIR)/latex
	@ln -s $(DOC_DIR)/latex/refman.pdf $(DOC_TARGET)

all: $(DOC_TARGET)

clean:
	@rm -rf $(DOC_DIR)/html $(DOC_DIR)/latex $(DOC_TARGET)
