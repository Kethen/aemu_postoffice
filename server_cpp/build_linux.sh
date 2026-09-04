set -xe

SRC="log native_socket_linux session server semaphore main ../adhocctl/server_cpp/log common ../adhocctl/server_cpp/client ../adhocctl/server_cpp/server ../adhocctl/server_cpp/snapshot file_util ../adhocctl/server_cpp/game_db config snapshot http_status_server"

BUILD_FLAGS="-g -O2 -fPIC --std=c++20 -Wformat"
LINK_FLAGS=""

CPPC=g++

built=""
for f in $SRC
do
	$CPPC $BUILD_FLAGS -c ${f}.cpp -o ${f}.o
	built="$built ${f}.o"
done

$CPPC $LINK_FLAGS $built -lpthread -o aemu_postoffice
