set -xe

CC=gcc
CPPC=g++

BUILD_FLAGS="-fPIC -g -O2 -Wformat"
DEBUG="${DEBUG:-false}"

if $DEBUG
then
	BUILD_FLAGS="-fPIC -g -O0 -fsanitize=address -Wformat"
fi

C_SRC="log_impl_stdc postoffice sock_impl_linux postoffice_mem_stdc ../adhocctl/client/adhocctl ../adhocctl/client/adhocctl_mem list enet"
CPP_SRC="mutex_impl_cpp delay_impl_cpp"
C_SRC_TEST="test"

lib_objs=""

$CC $BUILD_FLAGS list.c list_test.c log_impl_stdc.c -o list_test.out
if $DEBUG
then
	./list_test.out
else
	valgrind ./list_test.out
fi

for f in $C_SRC
do
	$CC $BUILD_FLAGS -c ${f}.c -o ${f}.o
	lib_objs="$lib_objs ${f}.o"
done

for f in $CPP_SRC
do
	$CPPC $BUILD_FLAGS -c ${f}.cpp -o ${f}.o
	lib_objs="$lib_objs ${f}.o"
done

test_objs=""
for f in $C_SRC_TEST
do
	$CC $BUILD_FLAGS -c ${f}.c -o ${f}.o
	test_objs="$test_objs ${f}.o"
done

$CPPC $BUILD_FLAGS $lib_objs $test_objs -lpthread -o test.out
$CPPC $BUILD_FLAGS -shared $lib_objs -lpthread -o libaemu_postoffice_client.so
