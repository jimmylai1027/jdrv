#!/bin/bash

if lsmod | grep "\<m\>" &> /dev/null ; then
	echo "rmmod m"
	rmmod m
fi

if [ -e m.ko ]; then
	echo "insert m.ko"
	insmod m.ko
else
	echo "m.ko does not exit."
	exit -1
fi

if [ ! -e /dev/mdrv ]; then
	# make device node for char driver 'mdrv' 
	# with major 60 and minor 0
	echo "mknod /dev/mdrv c 60 0"
	mknod /dev/mdrv c 60 0
	# change file mode with rw
	chmod 666 /dev/mdrv
fi

