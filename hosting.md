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

#### Configuring the server

`config.json` next to `aemu_postoffice`/`aemu_postoffice.exe` is loaded on server start. See [here](/server_cpp/config.h) for explanations of each configuration item

#### Migrating crosslink database from standalone adhocctl server

A game database conversion script `server_cpp/db_convert.js` is provided is provided with the release bundle from https://github.com/Kethen/aemu_postoffice/releases . The script requires nodejs to run.

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
