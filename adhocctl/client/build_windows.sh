set -xe

CC=x86_64-w64-mingw32-gcc
CPPC=x86_64-w64-mingw32-g++

BUILD_FLAGS="-fPIC -g -O2 -Wformat"

$CC $BUILD_FLAGS -c adhocctl.c -o adhocctl.o
$CC $BUILD_FLAGS -c adhocctl_mem.c -o adhocctl_mem.o
$CC $BUILD_FLAGS -c ../../client/sock_impl_windows.c -o sock_impl_windows.o
$CC $BUILD_FLAGS -c ../../client/log_impl_stdc.c -o log_impl_stdc.o
$CC $BUILD_FLAGS -c ../../client/list.c -o list.o
$CPPC $BUILD_FLAGS -c ../../client/delay_impl_cpp.cpp -o delay.o
$CC $BUILD_FLAGS -c ../../client/enet.c -o enet.o
$CPPC $BUILD_FLAGS -c ../../client/mutex_impl_cpp.cpp -o mutex_impl.o
$CC $BUILD_FLAGS -c test.c -o test.o

$CPPC $BUILD_FLAGS -static adhocctl.o adhocctl_mem.o sock_impl_windows.o log_impl_stdc.o mutex_impl.o delay.o list.o enet.o test.o -lws2_32 -lwinmm -o test.exe
$CPPC $BUILD_FLAGS -shared -static adhocctl.o adhocctl_mem.o sock_impl_windows.o log_impl_stdc.o mutex_impl.o delay.o list.o enet.o -lws2_32 -lwinmm -o libadhocctl.dll
