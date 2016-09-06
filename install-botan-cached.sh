#!/bin/sh
set -e
if [ ! -f "$HOME/botan/lib/libbotan-1.10.a" ]; then
  wget --no-check-certificate http://botan.randombit.net/releases/Botan-1.10.12.tgz && \
  tar -xzvf Botan-1.10.12.tgz                                && \
  cd Botan-1.10.12                                           && \
  ./configure.py --prefix=$HOME/botan                        && \
  make                                                       && \
  make install                                               && \
  echo -e "[\E[32m\033[1m OK \033[0m] Botan install Success" || \
  (echo -e "[\E[31m\033[1mFAIL\033[0m] Botan install Failed" && \
  exit 1)
else
  echo 'Using cached Botan installation.';
fi
