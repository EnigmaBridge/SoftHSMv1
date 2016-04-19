#!/bin/sh

#./configure --with-botan=/usr && \

sh autogen.sh && \
./configure --with-loglevel=4 --with-botan=$HOME/botan && \
make all && \
export LD_PRELOAD=$HOME/botan/lib/libbotan-1.10.so.1 && \
make check

#make all check
