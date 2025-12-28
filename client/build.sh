set -xe
gcc -fPIC -g -c test.c -o test.o -O0
gcc -fPIC -g -c postoffice.c -o postoffice.o -O2
gcc -fPIC -g -c sock_impl_linux.c -o sock_impl_linux.o -O2
gcc -fPIC -g -c mutex_impl_linux.c -o mutex_impl_linux.o -O2

gcc -O0 test.o postoffice.o sock_impl_linux.o mutex_impl_linux.o -o test.out
gcc -fPIC -shared postoffice.o sock_impl_linux.o mutex_impl_linux.o -o libaemu_postoffice_client.so
