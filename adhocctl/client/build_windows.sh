set -xe

CC=x86_64-w64-mingw32-gcc
CPPC=x86_64-w64-mingw32-g++

BUILD_FLAGS="-fPIC -g -O2 -Wformat"

$CC $BUILD_FLAGS -c adhocctl.c -o adhocctl.o
$CC $BUILD_FLAGS -c ../../client/sock_impl_windows.c -o sock_impl_windows.o
$CC $BUILD_FLAGS -c ../../client/log_impl_stdc.c -o log_impl_stdc.o
$CC $BUILD_FLAGS -c test.c -o test.o

$CPPC $BUILD_FLAGS -static adhocctl.o sock_impl_windows.o log_impl_stdc.o test.o -lws2_32 -o test.exe
$CPPC $BUILD_FLAGS -shared -static adhocctl.o sock_impl_windows.o log_impl_stdc.o -lws2_32 -o libadhocctl.dll
