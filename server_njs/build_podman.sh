set -xe

IMAGE=aemu_postoffice_ts_builder

DEBUG=${DEBUG:-false}

if ! podman image exists $IMAGE
then
	podman image build -t $IMAGE -f Dockerfile
fi

podman run \
	--rm -it \
	-v ./:/work_dir \
	-w /work_dir \
	$IMAGE \
	tsc --typeRoots '/usr/local/lib/node_modules/@types' --types 'node' --noImplicitAny aemu_postoffice.ts
