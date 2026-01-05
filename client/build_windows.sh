set -xe
GCC=x86_64-w64-mingw32-gcc

$GCC -fPIC -g -c test.c -o test.o -O0
$GCC -fPIC -g -c postoffice.c -o postoffice.o -O2
$GCC -fPIC -g -c sock_impl_windows.c -o sock_impl_windows.o -O2
$GCC -fPIC -g -c mutex_impl_windows.c -o mutex_impl_windows.o -O2

$GCC -O0 -static test.o postoffice.o sock_impl_windows.o mutex_impl_windows.o -lws2_32 -lpthread -o test.exe
$GCC -fPIC -shared -static postoffice.o sock_impl_windows.o mutex_impl_windows.o -lws2_32 -o libaemu_postoffice_client.dll
