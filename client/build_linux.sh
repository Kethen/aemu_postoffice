set -xe
gcc -fPIC -g -c log_impl_stdc.c -o log_impl_stdc.o -O2
gcc -fPIC -g -c test.c -o test.o -O0
gcc -fPIC -g -c postoffice.c -o postoffice.o -O2
gcc -fPIC -g -c sock_impl_linux.c -o sock_impl_linux.o -O2
g++ -fPIC -g -c mutex_impl_cpp.cpp -o mutex_impl_cpp.o -O2
g++ -fPIC -g -c delay_impl_cpp.cpp -o delay_impl_cpp.o -O2
gcc -fPIC -g -c postoffice_mem_stdc.c -o postoffice_mem_stdc.o -O2

g++ -O0 log_impl_stdc.o test.o postoffice.o sock_impl_linux.o mutex_impl_cpp.o delay_impl_cpp.o postoffice_mem_stdc.o -o test.out
g++ -fPIC -shared log_impl_stdc.o postoffice.o sock_impl_linux.o mutex_impl_cpp.o delay_impl_cpp.o postoffice_mem_stdc.o -o libaemu_postoffice_client.so
