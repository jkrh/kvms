#!/bin/bash

POORPIPE=${BASE_DIR}/poorpipe
rm -f $POORPIPE
mkfifo $POORPIPE
trap '' SIGINT

#
# Amount of samples collected per round and reported in one bundle
#
NSAMPLES=60

#
# Polling period, seconds
#
INTERVAL="0.5"

run-gdb()
{
	exec ${CROSS_COMPILE}gdb -q -ex "target remote localhost:1234" -ex "set confirm off" \
		-ex "add-symbol-file ${PROG} 0xC0001000" -ex "set pagination 0" -ex "handle signal SIGINT stop" \
		${VMLINUX} 1> $POORPIPE 2> $POORPIPE << EOF
define runloop
while (1)
t a a bt
echo Ö
continue
end
end
runloop
EOF
}

do-reads()
{
	I=0
	DATABUF=""
	while [[ $I -lt $NSAMPLES ]] ; do
		read -d Ö data
		DATABUF+="$data"
		((I++))
	done < $POORPIPE
}

do-poorman()
{
		echo "$DATABUF" | awk '
BEGIN { s = ""; }
/^Thread/ { print s; s = ""; }
/^#/ { if (s != "" ) { s = s "," $4} else { s = $4 } }
END { print s }' | \
		sort | uniq -c | sort -r -n -k 1,1
}

do-wakeups()
{
	while true; do
		sleep $INTERVAL
		kill -s SIGINT $GDBPID > /dev/null 2>&1
		if [ $? != 0 ]; then
			echo "gdb disappeared, exiting"
			exit 0
		fi
	done
}

cleanup()
{
	kill $(jobs -p) > /dev/null 2>&1
	rm -f $POORPIPE
	exit 0
}

trap cleanup PWR HUP INT TERM EXIT

run-gdb &
GDBPID=$!
sleep 3
do-wakeups &

while true; do
	echo ""
	echo "Collecting samples.."
	echo ""
	do-reads
	do-poorman
done
