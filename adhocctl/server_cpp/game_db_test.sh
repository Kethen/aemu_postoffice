set -xe
g++ --std=c++20 game_db_test.cpp game_db.cpp log.cpp ../../server_cpp/log.cpp ../../server_cpp/file_util.cpp -o game_db_test.out
./game_db_test.out
