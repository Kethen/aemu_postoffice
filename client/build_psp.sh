source /etc/profile.d/pspsdk.sh

set -xe

gcc_build_args="-Os -fno-builtin -G0 -Wall -fno-pic -I/usr/local/pspdev/psp/sdk/include -D_PSP_FW_VERSION=600"
gcc_prx_args="-L/usr/local/pspdev/psp/sdk/lib -specs=/usr/local/pspdev/psp/sdk/lib/prxspecs -Wl,-q,-T/usr/local/pspdev/psp/sdk/lib/linkfile.prx -nostartfiles -Wl,-zmax-page-size=128"
gcc_prx_libs="-nostdlib -lpspuser -lpspsdk -lpspmodinfo -lpspnet_inet"

psp-gcc $gcc_build_args -c sock_impl_psp.c -o sock_impl_psp.o
psp-gcc $gcc_build_args -c mutex_impl_psp.c -o mutex_impl_psp.o
psp-gcc $gcc_build_args -c postoffice.c -o postoffice.o
psp-gcc $gcc_build_args -c psp_main.c -o psp_main.o
psp-build-exports -b postoffice_client.exp > exports.c
psp-gcc $gcc_build_args -c exports.c -o exports.o
rm exports.c

psp-gcc $gcc_prx_args psp_main.o sock_impl_psp.o mutex_impl_psp.o postoffice.o exports.o -o postoffice.elf $gcc_prx_libs

psp-fixup-imports postoffice.elf
psp-prxgen postoffice.elf postoffice.prx
