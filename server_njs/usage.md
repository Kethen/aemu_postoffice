### Start server

#### Linux/WSL with podman installed:

Terminal:
```
# Switch current directory to where you have extracted the release
cd server_njs

# remove nodejs docker image so that it gets updated later, you can skip this if you want
podman image rm node:slim

# fetch newest nodejs docker image if not available and run aemu_postoffice.js through it, with old space set to 500MB and semi space set to 128MB
MAX_OLD_SPACE_MB=500 MAX_SEMI_SPACE_MB=128 bash run_podman.sh
```

#### Linux/WSL with node installed from distro:

Terminal:
```
# Switch current directory to where you have extracted the release
cd server_njs

# run aemu_postoffice.js with old space set to 500MB and semi space set to 128MB
node --max-old-space-size=500 --max-semi-space-size=128 aemu_postoffice.js
```

#### Windows with node installed from official website

cmd:
```
# Switch current directory to where you have extracted the release
cd server_njs

# run aemu_postoffice.js with old space set to 500MB and semi space set to 128MB
node --max-old-space-size=500 --max-semi-space-size=128 aemu_postoffice.js
```

### Configuration with `config.json`

```
{
	"connection_strict_mode":false,
	"forwarding_strict_mode":false,
	"max_per_second_data_rate_byte":0,
	"max_tx_op_rate":0,
	"max_write_buffer_byte":512000,
}
```

| Name | Description |
| -- | -- |
| connection_strict_mode | WIP subjected to changes. Limit new connection to adhocctl clients registered with http://:27314/game_list_sync , sample api expected json can be found at [sample_game_list_sync_request.json](sample_game_list_sync_request.json) |
| forwarding_strict_mode | WIP subjected to changes. Limit data transmission within adhocctl client groups registered with http://:27314/game_list_sync , sample api expected json can be found at [sample_game_list_sync_request.json](sample_game_list_sync_request.json) |
| max_per_second_data_rate_byte | Evict sessions by IP address that exceeds this data rate (per second). Be cautious with this option as multiple clients can be from the same ip address. Set to 0 to disable. |
| max_tx_op_rate | Evict sessions by IP address that exceeds send operation rate (per second). Be cautious with this option as multiple clients can be from the same ip address. Set to 0 to disable. |
| max_write_buffer_byte | Evict sessions that are not receiving data correctly and causing send buffers to bloat. Set to 0 to disable. |
