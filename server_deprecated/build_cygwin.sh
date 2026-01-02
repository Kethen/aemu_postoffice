set -xe

IMAGE=pspsdk_aemu_postoffice_cygwin

if ! podman image exists $IMAGE
then
	podman image build -t $IMAGE -f Dockerfile_cygwin
fi

podman run \
	--rm -it \
	-v ../:/work_dir \
	-w /work_dir/server \
	--entrypoint '["/bin/bash", "-c"]' \
	$IMAGE \
	'
	set -xe
	x86_64-pc-cygwin-g++ *.c *.cpp -o aemu_postoffice_server.exe --static
	cp /usr/x86_64-pc-cygwin/sys-root/usr/bin/cygwin1.dll ./
'
