# Flexisip

Flexisip is a comprehensive, modular and scalable SIP server suite written in C++17. It offers a wide range of
functionalities, including:

* **Proxy Server**: acts as a central hub for routing SIP messages.
    * **Push Notification Service**: delivers SIP notifications (in-calls, messages) to mobile devices even when the app
      is not actively running.
* **Presence Server**: enables users to see the online status of others and their availability for calls.
* **Conference Server**: enables group voice and video calls.
* **Back-to-Back User Agent (B2BUA) Server**: enables caller identity translation, media-level transcoding and SIP
  trunking.
* **RegEvent Server**: notify tier domains of user registration.

## Deployment and Applications:

* **Server-based VoIP Service**: Flexisip can be deployed on server machines to run a full-fledged SIP VoIP service.
  This is exemplified by the free linphone.org service, which has been powered by Flexisip since 2011. Users can create
  SIP accounts on this service to connect with each other.
* **Embedded Solutions**: Flexisip can also be embedded and run seamlessly on smaller hardware systems, making it
  suitable for various embedded applications.

# License

Copyright © Belledonne Communications

Flexisip is dual licensed, and can be licensed and distributed:

- under a GNU Affero GPLv3 license for free (see COPYING file for details)
- under a proprietary license, for closed source projects. Contact Belledonne Communications for any question about
  [costs and services](https://www.linphone.org/en/flexisip-sip-server/#flexisip-license).

# Documentation

- [Supported features and RFCs](https://www.linphone.org/en/flexisip-sip-server/#flexisip-software)
- [Flexisip documentation](https://www.linphone.org/en/flexisip-sip-server/#flexisip-documentation)

# Dependencies

| Dependency      | Description                                                                                                                           | Mandatory | Enabled by default |
|:----------------|:--------------------------------------------------------------------------------------------------------------------------------------|:---------:|:------------------:|
| OpenSSL         | TLS stack.                                                                                                                            |     X     |                    |
| LibNgHttp2      | HTTP2 stack.                                                                                                                          |     X     |                    |
| libsrtp2        | Secure RTP (SRTP) and UST Reference Implementations                                                                                   |     X     |                    |
| SQLite3         | Library for handling SQlite3 file                                                                                                     |     X     |                    |
| libmysql-client | Client library for MySQL database.                                                                                                    |     X     |                    |
| Hiredis         | Redis DB client library, used for Registrar DB and communications between Flexisip instances of a same cluster. (-DENABLE\_REDIS=YES) |           |         X          |
| NetSNMP         | SNMP library, used for SNMP support. (-DENABME\_SNMP=YES)                                                                             |           |         X          |
| XercesC         | XML parser. (-DENABLE\_PRESENCE=YES)                                                                                                  |           |         X          |
| jsoncpp         | JSON parsing and writing (-DENABLE\_B2BUA=YES)                                                                                        |           |         X          |
| cpp-jwt         | JSON Web Token support (-DENABLE\_OPENID\_CONNECT=YES)                                                                                |           |         X          |

# Compilation

## Required build tools

- C and C++ compiler. GCC and Clang are supported *as long as they are recent enough for building C++17 code*. On
  Redhat/CentOS 7, we recommend installing gcc-7 from https://www.softwarecollections.org/en/scls/rhscl/devtoolset-7/ .
  The default gcc-4.8 is not sufficient.
- CMake >= 3.13
- make or Ninja
- Python >= 3
- Doxygen
- Git

## Building Flexisip with CMake

Create a build directory and configure the project:

### From cloned GIT repository

```bash
mkdir ./build
cmake -S . -B ./build
make -C ./build -j<njobs>
```

### Custom
When built outside a git repository, you have to manually mention Flexisip and Linphone-SDK versions.

```bash
mkdir ./build
cmake -S . -B ./build -DFLEXISIP_VERSION=<version> -DLINPHONESDK_VERSION=<version>
make -C ./build -j<njobs>
```

### Some tips

Check *CMakeLists.txt* to know the list of the available options and their default value. To change an option, invoke
*CMake* again and specify the option you need to change.
For instance, here is how to disable the presence server feature:

```bash
cmake ./build -DENABLE_PRESENCE=OFF
make -C ./build -j<njobs>
```

You may also use *ccmake* or *cmake-gui* utilities to interactively configure the project:

```bash
ccmake ./build
make -C ./build -j<njobs>
```

## Building RPM or DEB packages

This procedure will help you generate a unique RPM package containing Flexisip, all its dependencies and the
corresponding package for debug symbols.
The following options are relevant for packaging:

| Option                 | Description                                                                |
|:-----------------------|:---------------------------------------------------------------------------|
| `CMAKE_INSTALL_PREFIX` | Prefix path where the package will install the files.                      |
| `SYSCONF_INSTALL_DIR`  | Directory where Flexisip expects to find its default configuration.        |
| `CMAKE_BUILD_TYPE`     | Set it to “RelWithDebInfo” to have debug symbols in the debuginfo package. |
| `CPACK_GENERATOR`      | Package type: “RPM” or “DEB”.                                              |

```bash
cmake ./build -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSYSCONF_INSTALL_DIR=/etc -DCPACK_GENERATOR=RPM
make -C ./build -j<njobs> package
```

Packages are now available in the `./build` directory.

[More info on RPM packaging](./packaging/rpm/README.md)

## Docker

A docker image can be built from sources using the following command:

```bash
docker build -t flexisip --build-arg='njobs=<njobs>' -f docker/flex-from-src .
```

## Nix ❄️

Flexisip can also be compiled with [Nix]. From the root of the repository, you can obtain a development shell using:

```sh
nix-shell
```

Or with Flakes enabled:

```sh
nix develop
```

Nix makes it easier to have a reproducible development environment on any Linux distribution, and doesn't interfere with
other installed tooling. It is just an additional, **optional** way to build flexisip.

### Example build commands:

```sh
CC=gcc CXX=g++ BUILD_DIR_NAME="build" cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -S . -B ./$BUILD_DIR_NAME -G "Ninja" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$PWD/$BUILD_DIR_NAME/install" -DENABLE_UNIT_TESTS=ON -DENABLE_STRICT_LINPHONESDK=OFF -DINTERNAL_JSONCPP=OFF
cd build
clear && cmake --build . --target install && LSAN_OPTIONS="suppressions=../sanitizer_ignore.txt" bin/flexisip_tester --resource-dir "../tester/" --verbose
```

### Note to maintainers

At the exception to [`shell.nix`](./shell.nix), `.nix` files should live inside the [`nix/`](./nix/) folder.

All `.nix` files should be formatted with `nixpkgs-fmt`.

[Nix]: https://nixos.org/

# Configuration

Flexisip needs a configuration file to run correctly.
Use `./flexisip --dump-all-default > flexisip.conf` to generate a documented default configuration file.

# Developer notes

With sofia-sip, you can choose between `msg_dup()` and `msg_copy()`, `sip_from_dup()` and `sip_from_copy()`, _etc_.
The difference isn't well documented in the sofia-sip documentation, but it is important to understand that:

- `*_dup()` makes a copy of the structure plus all included strings inside (deep copy).
- `*_copy()` just makes a copy of the structure, not the strings pointed by it (shallow copy). **These functions are
  dangerous**; use `*_dup()` versions in doubt.