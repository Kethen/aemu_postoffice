set -xe
g++ --std=c++20 config_test.cpp config.cpp log.cpp native_socket_linux.cpp file_util.cpp -o config_test.out
./config_test.out
