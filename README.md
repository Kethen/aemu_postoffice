### aemu_postoffice

PSP adhoc data forwarder protocol and implementation, for easy and reliable adhoc multiplayer through internet

Current users:
- [PSP internet adhoc plugin aemu](https://github.com/kethen/aemu)
- [PPSSPP](http://github.com/hrydgard/ppsspp)

#### Current design

See [design.md](/design.md)

#### Client implementation

See [./client/postoffice.c](/client/postoffice.c) and [./adhocctl/client/adhocctl.c](/adhocctl/client/adhocctl.c)

##### Building and testing

Linux:

```
# Ubuntu/Debian:
sudo apt install podman git

# OpenSUSE
sudo zypper install podman git

# Fedora
sudo dnf install podman git

# Clone project and build client
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/client
bash build_podman.sh

# Run tests, requires relay server on localhost running (see below)
./test.out
```

MacOS/FreeBSD:

```
# FreeBSD
sudo pkg install git gcc bash

# Clone project and build client, on MacOS, you might be prompted to install xcode commandline tools in this step if you do not have any version of xcode around
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/client
bash build_linux.sh

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

See [./server_cpp](/server_cpp) and [./adhocctl/server_cpp](/adhocctl/server_cpp)

##### Building and running

Linux:

```
# Ubuntu/Debian:
sudo apt install podman git

# OpenSUSE
sudo zypper install podman git

# Fedora
sudo dnf install podman git

# Clone project and build server
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/server_cpp
bash build_podman.sh

# Run server
./aemu_postoffice
```

MacOS/FreeBSD:

```
# FreeBSD
sudo pkg install git gcc bash

# Clone project and build client, on MacOS, you might be prompted to install xcode commandline tools in this step if you do not have any version of xcode around
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/client
bash build_linux.sh

# Run server
./aemu_postoffice
```

Windows:

1. install https://cygwin.com/ , pick packages `mingw64-x86_64-gcc`, `mingw64-x86_64-gcc-g++` and `git`
2. open a cygwin shell

```
# Clone project and build server
git clone https://github.com/kethen/aemu_postoffice
cd aemu_postoffice/server_cpp
bash build_windows.sh

# Run server
./aemu_postoffice.exe
```
