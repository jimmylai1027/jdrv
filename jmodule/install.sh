#!/bin/bash

if lsmod | grep "j" &> /dev/null ; then
	echo "rmmod j"
	rmmod j
fi

if [ -e j.ko ]; then
	echo "insert j.ko"
	insmod j.ko
else
	echo "j.ko does not exit."
	exit -1
fi

if [ ! -e /dev/jdrv ]; then
	# make device node for char driver 'jdrv' 
	# with major 60 and minor 0
	echo "mknod /dev/jdrv c 60 0"
	mknod /dev/jdrv c 60 0
	# change file mode with rw
	chmod 666 /dev/jdrv
fi

