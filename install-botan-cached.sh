!/bin/sh
set -e
if [ ! -f "$HOME/botan/botan" ]; then
  wget http://botan.randombit.net/releases/Botan-1.10.12.tgz && \
  tar -xzvf Botan-1.10.12.tgz                                && \
  cd Botan-1.10.12                                           && \
  ./configure.py --prefix=$HOME/botan                        && \
  make                                                       && \
  ./botan-test                                               && \
  make install                                               && \
  echo -e "[\E[32m\033[1m OK \033[0m] Success"               || \
  echo -e "[\E[31m\033[1mFAIL\033[0m] Update failed"         && \
  exit 1
else
  echo 'Using cached directory.';
fi
