# SPDX-License-Identifier: GPL-2.0-only
#
# Define the paging data stash size for each VM. This is the amount
# of pages (small or large) each VM can store in the page integrity
# stash.
#
ifndef MAX_PAGING_BLOCKS
MAX_PAGING_BLOCKS := 16384
endif
