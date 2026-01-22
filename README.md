### aemu_postoffice

PSP adhoc data forwarder protocol and implementation, for easy and reliable adhoc multiplayer through internet

Current users:
- [PSP internet adhoc plugin aemu](https://github.com/kethen/aemu)
- [PPSSPP](http://github.com/hrydgard/ppsspp)

#### Current design

See [design.md](/design.md)

#### Client implementation

See [./client](/client)

##### Building and testing

Linux:

```
# Ubuntu/Debian:
apt install podman git

# OpenSUSE
zypper install podman git

# Fedora
dnf install podman git

# Clone project and build client
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/client
bash build_podman.sh

# Run tests, requires relay server on localhost running (see below)
./test.out
```

Windows:

1. install https://cygwin.com/ , pick packages `mingw64-x86_64-gcc`, `mingw64-x86_64-gcc-g++` and `git`
2. open a cygwin shell

```
# Clone project and build client
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/client
bash build_windows.sh

# Run tests, requires relay server on localhost running (see below)
./test.exe
```

#### Server implementation

See [./server_njs](/server_njs)

##### Running

Linux using distro packaged nodejs:

```
# Ubuntu/Debian:
apt install nodejs git

# OpenSUSE
zypper install nodejs git

# Fedora
dnf install nodejs git

# Clone project
git clone https://github.com/kethen/aemu_postoffice

# Run server
cd aemu_postoffice/server_njs
node aemu_postoffice.js
```

Linux using podman:

```
# Ubuntu/Debian:
apt install podman git

# OpenSUSE
zypper install podman git

# Fedora
dnf install podman git

# Clone project
git clone https://github.com/kethen/aemu_postoffice

# Run server
cd aemu_postoffice/server_njs
bash run_podman.sh

```

Windows:

1. install https://nodejs.org/en/download
2. open `aemu_postoffice.js` using nodejs
