set -xe
gcc -fPIC -g -c test.c -o test.o -O0
gcc -fPIC -g -c postoffice.c -o postoffice.o -O2

g++ test.o postoffice.o -o test.out
g++ -fPIC -shared postoffice.o -o libaemu_postoffice_client.so
