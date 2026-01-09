IMAGE=aemu_postoffice_njs_server

if ! podman image exists $IMAGE
then
	podman image build -t $IMAGE -f Dockerfile
fi

podman run \
	--rm -it \
	-p 27313:27313 \
	-p 27314:27314 \
	--entrypoint "/usr/bin/node" \
	-v ./aemu_postoffice.js:/aemu_postoffice.js:ro \
	$IMAGE \
	aemu_postoffice.js
