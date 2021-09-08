Flexisip is a complete, modular and scalable SIP server suite written in C++14, comprising proxy, presence and group chat functions.
It also includes a push gateway, to deliver SIP incoming calls or text messages on mobile device platforms where push notifications are required to receive information when the app is not active in the foreground.

Flexisip instances can be deployed on server machines to run a SIP VoIP service. 
The free linphone.org SIP service has run on Flexisip since 2011, and enables Linphone users to create SIP addresses in order to connect with each other.

It can also be embedded and run perfectly on small hardware systems.

# License

Copyright © Belledonne Communications

Flexisip is dual licensed, and can be licensed and distributed:
- under a GNU Affero GPLv3 license for free (see COPYING file for details)
- under a proprietary license, for closed source projects. Contact Belledonne Communications for any question about costs and services.

# Documentation

- [Supported features and RFCs](https://www.linphone.org/technical-corner/flexisip/features)
- [Flexisip documentation](https://www.linphone.org/technical-corner/flexisip/documentation)

# Dependencies

| Dependency      | Description                                                                                                                              | Mandatory | Enabled by default |
| :---            | :---                                                                                                                                     | :---:     | :---:              |
| OpenSSL         | TLS stack.                                                                                                                               | X         |                    |
| LibNgHttp2      | HTTP2 stack.                                                                                                                             | X         |                    |
| SQLite3         | Library for handling SQlite3 file                                                                                                        | X         |                    |
| libmysql-client | Client library for MySQL database.                                                                                                       | X         |                    |
| Hiredis         | Redis DB client library, used for Registrar DB and communications between Flexisip instances of a same cluster. (-DENABLE\_REDIS=YES)    |           | X                  |
| Protobuf        | Needed for migration from legacy registrar database format. (-DENABLE\_PROTOBUF=YES)                                                     |           | X                  |
| NetSNMP         | SNMP library, used for SNMP support. (-DENABME\_SNMP=YES)                                                                                |           | X                  |
| XercesC         | XML parser. (-DENABLE\_PRESENCE=YES)                                                                                                     |           | X                  |


# Compilation

## Required build tools

- C and C++ compiler. GCC and Clang are supported *as long as they are recent enough for building C++14 code*.
  On Redhat/CentOS 7, we recommend installing gcc-7 from https://www.softwarecollections.org/en/scls/rhscl/devtoolset-7/ . The default gcc-4.8 is not sufficient.
- CMake >= 3.13
- make or Ninja
- Python >= 3
- Doxygen
- Git


## Building Flexisip with CMake

Create a build directory and configure the project:

```bash
mkdir ./build
cmake -S . -B ./build
make -C ./build -j<njobs>
```

Check *CMakeLists.txt* to know the list of the available options and their default value. To change an option, you just need to invoke *CMake* again by specifying the option you need to change only.
For instance, to disable the presence server feature:

```bash
cmake ./build -DENABLE_PRESENCE=OFF
make -C ./build -j<njobs>
```

You may also use *ccmake* or *cmake-gui* utilities to configure the project interactively:

```bash
ccmake ./build
make -C ./build -j<njobs>
```

## Building RPM or DEB packages

This procedure will make a unique RPM package containing Flexisip and all its dependencies and the according package for debug symbols.

The following options are relevant for packaging:

|                        |                                                                              |
| :---                   | :---                                                                         |
| `CMAKE_INSTALL_PREFIX` | The prefix where the package will installed the files.                       |
| `SYSCONF_INSTALL_DIR`  | Where Flexisip expect to find its default configuration directory.           |
| `CMAKE_BUILD_TYPE`     | Set this to “RelWithDebInfo” to have debug symbols in the debuginfo package. |
| `CPACK_GENERATOR`      | Select the kind of package. “RPM” or “DEB”.                                  |

```bash
cmake ./build -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communiactions -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSYSCONF_INSTALL_DIR=/etc -DCPACK_GENERATOR=RPM
make -C ./build -j<njobs> package
```

The packages are now available in ./build directory.

## Docker

A docker image can be build from sources with command:

```bash
docker build -t flexisip --build-arg='njobs=<njobs>' -f docker/flex-from-src .
```

# Configuration

Flexisip needs a configuration file to run correctly.
Use `./flexisip --dump-all-default > flexisip.conf` to make a documented
default configuration file.

# Developer notes

With sofia-sip, you have the choice between `msg_dup()` and `msg_copy()`,
`sip_from_dup()` and `sip_from_copy()`, _etc_.
The difference isn't well documented in sofia-sip documentation but it is
important to understand that:
- `*_dup()` makes a copy of the structure plus all included strings inside.
- `*_copy()` just makes a copy of the structure, not the strings pointed by it. **These functions are
dangerous**; use `*_dup()` versions in doubt.
