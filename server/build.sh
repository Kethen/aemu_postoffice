set -xe
gcc -fPIC -g -c main.c -o main.o -O2
gcc -fPIC -g -c log.c -o log.o -O2
g++ -fPIC -std=c++20 -g -c postoffice.cpp -o postoffice.o -O2

g++ main.o log.o postoffice.o -o aemu_postoffice_server.out
g++ -fPIC -shared log.o postoffice.o -o libaemu_postoffice_server.so
