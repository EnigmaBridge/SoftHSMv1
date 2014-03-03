#!/bin/sh

PREFIX=/tmp/softhsm-release

if [ ! -f autogen.sh -a ! -f configure ]; then
        echo "Unable to continue, no autogen.sh or configure"
        exit 1
fi

if [ -f autogen.sh ]; then 
        sh autogen.sh 
fi &&
mkdir -p build &&
cd build &&
../configure --prefix=${PREFIX} \
	--with-botan=/usr \
	$@
