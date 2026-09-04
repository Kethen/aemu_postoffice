### Hosting guide

#### Running the server

Linux:

1. Download latest release from https://github.com/Kethen/aemu_postoffice/releases
2. Extract release zip
3. Run `server_cpp/aemu_postoffice` in a terminal

Windows:

1. Download latest release from https://github.com/Kethen/aemu_postoffice/releases
2. Extract release zip
3. Run `server_cpp/aemu_postoffice.exe`

MacOS/FreeBSD:

Build and run server following the instructions [here](/README.md#building-and-running)

#### Ports

By default, port `27312/tcp` is used for adhocctl, `27313/tcp` is used for relay, `8888/tcp` is used for the http status page. Please configure your firewall accordingly.

#### Configuring the server

`config.json` next to `aemu_postoffice`/`aemu_postoffice.exe` is loaded on server start. See [here](/server_cpp/config.h) for explanations of each configuration item

#### Customizing the http status page

- `http_assets` is statically served on http path `/assets`
- `http_assets/status.html` is served on http path `/` and can be customized/rewritten to your liking
- http path `/data.json` serves a server status json that is used by PPSSPP and the provided `http_assets/status.html` template

#### Migrating crosslink database from standalone adhocctl server

A game database conversion script `server_cpp/db_convert.js` is provided with the release bundle from https://github.com/Kethen/aemu_postoffice/releases . The script requires nodejs to run.

Linux/FreeBSD:

```
# Install nodejs
# Ubuntu/Debian:
sudo apt install nodejs

# OpenSUSE
sudo zypper install nodejs

# Fedora
sudo dnf install nodejs

# FreeBSD
sudo dnf install node26


# convert the database, overwrite game_db.json came with with release
node db_convert.js <database.db input path> <game_db.json output path, overwritting the one from the release>
```

Windows/MacOS:

1. Install nodejs following https://nodejs.org/en/download
2. Run the following in a shell/cmd

```
node db_convert.js <database.db input path> <game_db.json output path, overwritting the one from the release>
```
