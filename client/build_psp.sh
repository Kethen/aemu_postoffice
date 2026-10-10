source /etc/profile.d/pspsdk.sh

set -xe

PSPDEV=${PSPDEV:-/usr/local/pspdev}

gcc_build_args="-Os -fno-builtin -G0 -Wall -fno-pic -I$PSPDEV/psp/sdk/include -D_PSP_FW_VERSION=600"
gcc_prx_args="-L$PSPDEV/psp/sdk/lib -specs=$PSPDEV/psp/sdk/lib/prxspecs -Wl,-q,-T$PSPDEV/psp/sdk/lib/linkfile.prx -nostartfiles -Wl,-zmax-page-size=128"
gcc_prx_libs="-nostdlib -lpspuser -lpspsdk -lpspmodinfo -lpspnet_inet"

OBJS=""
SRC="log_impl_psp sock_impl_psp mutex_impl_psp delay_impl_psp postoffice psp_main postoffice_mem_psp exports"
ASM="ATPRO"

psp-build-exports -b postoffice_client.exp > exports.c

for S in $SRC
do
	psp-gcc $gcc_build_args -c ${S}.c -o ${S}.o
	OBJS="$OBJS ${S}.o"
done

rm exports.c

for S in $ASM
do
	psp-gcc $gcc_build_args -c ${S}.S -o ${S}.o
	OBJS="$OBJS ${S}.o"
done

psp-gcc $gcc_prx_args $OBJS -o postoffice.elf $gcc_prx_libs
psp-fixup-imports postoffice.elf
psp-prxgen postoffice.elf aemu_postoffice.prx
