IMAGE=aemu_postoffice_njs_server

if ! podman image exists $IMAGE
then
	podman image build -t $IMAGE -f Dockerfile
fi

podman run \
	--rm -it \
	-p 27313:27313 \
	--entrypoint "/usr/bin/node" \
	-v ./postoffice.js:/postoffice.js:ro \
	$IMAGE \
	postoffice.js
