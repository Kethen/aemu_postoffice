IMAGE=node:slim

podman run \
	--rm -it \
	-p 27313:27313 \
	-p 27314:27314 \
	-v ./aemu_postoffice.js:/aemu_postoffice.js:ro \
	-v ./config.json:/config.json:ro \
	$IMAGE \
	aemu_postoffice.js
