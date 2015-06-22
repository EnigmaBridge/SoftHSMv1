cmake_minimum_required(VERSION 3.2)
project(SoftHSMv1)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(.
../openssl-1.0.1i/include
src/lib
src/common
src/json
src/lib/cryptoki_compat/
src/lib/cryptoki_compat/pkcs11.h
/opt/local/include/botan-1.10)

set(SOURCE_FILES
    checks/checks.c
    checks/checks.h
    checks/cryptoki.h
    src/bin/base64.c
    src/bin/cryptoki.h
    src/bin/softhsm-keyconv.cpp
    src/bin/softhsm-keyconv.h
    src/bin/softhsm.cpp
    src/bin/softhsm.h
    src/lib/cryptoki_compat/pkcs11.h
    src/lib/attribute.cpp
    src/lib/attribute.h
    src/lib/botan_compat.cpp
    src/lib/botan_compat.h
    src/lib/cryptoki.h
    src/lib/file.cpp
    src/lib/file.h
    src/lib/log.cpp
    src/lib/log.h
    src/lib/main.cpp
    src/lib/main.h
    src/lib/mechanisms.cpp
    src/lib/mechanisms.h
    src/lib/MutexFactory.cpp
    src/lib/MutexFactory.h
    src/lib/osmutex.cpp
    src/lib/osmutex.h
    src/lib/SoftDatabase.cpp
    src/lib/SoftDatabase.h
    src/lib/SoftFind.cpp
    src/lib/SoftFind.h
    src/lib/SoftHSMInternal.cpp
    src/lib/SoftHSMInternal.h
    src/lib/SoftKeyStore.cpp
    src/lib/SoftKeyStore.h
    src/lib/SoftSession.cpp
    src/lib/SoftSession.h
    src/lib/SoftSlot.cpp
    src/lib/SoftSlot.h
    src/lib/tokenhandling.cpp
    src/lib/tokenhandling.h
    src/lib/userhandling.cpp
    src/lib/userhandling.h
    src/lib/util.h
    src/lib/jsoncpp.cpp)

add_executable(SoftHSMv1 ${SOURCE_FILES} src/lib/PK_Decryptor_EME_Remote.cpp src/lib/PK_Decryptor_EME_Remote.h src/lib/ShsmConnectionConfig.cpp src/lib/ShsmConnectionConfig.h src/lib/ShsmPrivateKey.cpp src/lib/ShsmPrivateKey.h src/lib/ShsmUtils.cpp src/lib/ShsmUtils.h src/common/ShsmApiUtils.cpp src/common/ShsmApiUtils.h)