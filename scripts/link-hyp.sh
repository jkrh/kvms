#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# link hyp
# link-hyp.sh ${1} ${2}
# ${1}: $(PROG)
# ${2}: $(PROGNAME)

export KALLSYMS=1
export KALLSYMS_ALL=1
#export KALLSYMS_ABSOLUTE_PERCPU=1
#export KALLSYMS_BASE_RELATIVE=1
#export KALLSYMS_EXTRA_PASS=1

# Error out on error
set -e

info()
{
	printf "  %-7s %s\n" ${1} ${2}
}

# Link of hyp
# ${1} - optional extra .o files
# ${2} - output file
hyp_link()
{
	local objects

	objects="${LDLIBS} ${1}"

	info LD ${2}
	${LD} ${LDFLAGS} -o ${2} ${objects} -static
}

# Create ${2} .o file with all symbols from the ${1} object file
kallsyms()
{
	info KSYM ${2}
	local kallsymopt;

	if [ -n "${KALLSYMS_ALL}" ]; then
		kallsymopt="${kallsymopt} --all-symbols"
	fi

	if [ -n "${KALLSYMS_ABSOLUTE_PERCPU}" ]; then
		kallsymopt="${kallsymopt} --absolute-percpu"
	fi

	if [ -n "${KALLSYMS_BASE_RELATIVE}" ]; then
		kallsymopt="${kallsymopt} --base-relative"
	fi

	local aflags="${AFLAGS}"
	local afile="`basename ${2} .o`.S"

	${NM} -n ${1} | ${BASE_DIR}/scripts/kallsyms ${kallsymopt} > ${afile}
	${CC} ${aflags} -c -o ${2} ${afile}
}

# Create map file with all symbols from ${1}
# See mksymap for additional details
mksysmap()
{
	${BASE_DIR}/scripts/mksysmap ${1} ${2}
}

# Delete output files in case of error
cleanup()
{
	rm -f .tmp_System.map
	rm -f .tmp_kallsyms*
	rm -f .tmp_hyp*
	rm -f System-hyp.map
}

on_exit()
{
	if [ $? -ne 0 ]; then
		cleanup
	fi
}
trap on_exit EXIT

on_signals()
{
	exit 1
}
trap on_signals HUP INT QUIT TERM

if [ "$1" = "clean" ]; then
	cleanup
	exit 0
fi

kallsymso=""
kallsyms_hyp=""
if [ -n "${KALLSYMS}" ]; then

	# kallsyms support
	# Generate section listing all symbols and add it into hyp
	# It's a three step process:
	# 1)  Link .tmp_hyp1 so it has all symbols and sections,
	#     but __kallsyms is empty.
	#     Running kallsyms on that gives us .tmp_kallsyms1.o with
	#     the right size
	# 2)  Link .tmp_hyp2 so it now has a __kallsyms section of
	#     the right size, but due to the added section, some
	#     addresses have shifted.
	#     From here, we generate a correct .tmp_kallsyms2.o
	# 3)  That link may have expanded the kernel image enough that
	#     more linker branch stubs / trampolines had to be added, which
	#     introduces new names, which further expands kallsyms. Do another
	#     pass if that is the case. In theory it's possible this results
	#     in even more stubs, but unlikely.
	#     KALLSYMS_EXTRA_PASS=1 may also used to debug or work around
	#     other bugs.
	# 4)  The correct ${kallsymso} is linked into the final hyp.
	#
	# a)  Verify that the System.map from hyp matches the map from
	#     ${kallsymso}.

	kallsymso=.tmp_kallsyms2.o
	kallsyms_hyp=.tmp_hyp2

	# step 1
	hyp_link "" .tmp_hyp1
	kallsyms .tmp_hyp1 .tmp_kallsyms1.o

	# step 2
	hyp_link .tmp_kallsyms1.o .tmp_hyp2
	kallsyms .tmp_hyp2 .tmp_kallsyms2.o

	# step 3
	if [ -n "${KALLSYMS_EXTRA_PASS}" ]; then
		kallsymso=.tmp_kallsyms3.o
		kallsyms_hyp=.tmp_hyp3

		hyp_link .tmp_kallsyms2.o .tmp_hyp3

		kallsyms .tmp_hyp3 .tmp_kallsyms3.o
	fi
fi

info LD ${1}
hyp_link "${kallsymso}" ${1}

info SYSMAP System-${2}.map
mksysmap ${1} System-${2}.map

# step a (see comment above)
if [ -n "${KALLSYMS}" ]; then
	mksysmap ${kallsyms_hyp} .tmp_System.map

	if ! cmp -s System-${2}.map .tmp_System.map; then
		echo >&2 Inconsistent kallsyms data
		echo >&2 Try "export KALLSYMS_EXTRA_PASS=1" as a workaround
		exit 1
	fi
fi
