#!/bin/sh

#./configure --with-botan=/usr && \

sh autogen.sh && \
./configure --with-botan=$HOME/botan && \
make all check
