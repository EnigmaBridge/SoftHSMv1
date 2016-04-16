#!/bin/bash
sh autogen.sh
./configure --with-loglevel=4 --with-botan=/usr
make

