#!/bin/sh

#./configure --with-botan=/usr && \

sh autogen.sh && \
./configure --with-loglevel=4 --with-botan=$HOME/botan && \
make all

#make all check
