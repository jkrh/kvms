#!/bin/sh -e

if [ X${COV_DIR} = X ]; then
	echo COV_DIR is not defined, set it to root of Coverity installation
	exit 1
fi

${COV_DIR}/bin/cov-configure --template --compiler ${CC} --comptype gcc
make DEBUG=${DEBUG} clean
rm -rf cov-dir cov-html
${COV_DIR}/bin/cov-build --dir cov-dir make DEBUG=${DEBUG}
${COV_DIR}/bin/cov-analyze --dir cov-dir --aggressiveness-level high --hfa --security --enable STACK_USE
${COV_DIR}/bin/cov-format-errors --dir cov-dir --html-output cov-html
