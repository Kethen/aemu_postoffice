set -xe

CC=gcc
CPPC=g++

BUILD_FLAGS="-fPIC -g -O2 -Wformat"

$CC $BUILD_FLAGS -c adhocctl.c -o adhocctl.o
$CC $BUILD_FLAGS -c adhocctl_mem.c -o adhocctl_mem.o
$CC $BUILD_FLAGS -c ../../client/sock_impl_linux.c -o sock_impl_linux.o
$CC $BUILD_FLAGS -c ../../client/log_impl_stdc.c -o log_impl_stdc.o
$CC $BUILD_FLAGS -c test.c -o test.o

$CPPC $BUILD_FLAGS adhocctl.o adhocctl_mem.o sock_impl_linux.o log_impl_stdc.o test.o -o test.out
$CPPC $BUILD_FLAGS -shared adhocctl.o adhocctl_mem.o sock_impl_linux.o log_impl_stdc.o -o libadhocctl.so
