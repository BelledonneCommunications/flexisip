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

The dependencies to install depend on the build utilities you use to build Flexisip (*./prepare.py* or *CMake*). See [“Compilations”](#compilation) for more information about build ways.

**Common and proxy dependencies:**

| Dependency      | Description                                                                                                                              | Mandatory | prepare.py | CMake |
| :---            | :---                                                                                                                                     | :---:     | :---:      | :---: |
| BcSofiaSip      | Belledonne Communications maintained SofiaSip project. [See GitLab repository](https://gitlab.linphone.org/BC/public/external/sofia-sip) | X         |            | X     |
| BcToolbox       | Several basic utilities.                                                                                                                 | X         |            | X     |
| BelR            | Generic parser using ABNF grammar, used for user file parsing.                                                                           | X         |            | X     |
| OpenSSL         | TLS stack.                                                                                                                               | X         | X          | X     |
| Hiredis         | Redis DB client library, used for Registrar DB and communications between Flexisip instances of a same cluster.                          | X         | X          | X     |
| LibNgHttp2      | HTTP2 stack.                                                                                                                             | X         | X          | X     |
| Soci            | SQL database client, used for user database reading and event logs.                                                                      | X         |            | X     |
| Soci-sqlite3    | Soci connector for SQLit3.                                                                                                               | X         |            | X     |
| Soci-mysql      | Soci connector for MySQL.                                                                                                                | X         |            | X     |
| SQLite3         |                                                                                                                                          | X         | X          |       |
| libmysql-client |                                                                                                                                          | X         | X          |       |
| oRTP            | RTP stack used for media relay feature.                                                                                                  | X         |            | X     |
| Mediastreamer   | Media engine used for transcoding feature.                                                                                               |           |            | X     |
| BelleSip        | mDNS support.                                                                                                                            |           |            | X     |
| Protobuf        | Needed for migration from legacy registrar database format.                                                                              |           | X          | X     |
| NetSNMP         | SNMP library, used for SNMP support.                                                                                                     |           | X          | X     |
| pdflatex        | To generate the reference documentation as PDF.                                                                                          |           | X          | X     |

**Presence server only dependencies:**

| Dependency      | Description                                                                                                                              | Mandatory | prepare.py | CMake |
| :---            | :---                                                                                                                                     | :---:     | :---:      | :---: |
| BelleSip        | SIP stack.                                                                                                                               | X         |            | X     |
| Xsd             | W3C XML Schema to C++ data binding compiler.                                                                                             | X         | X          | X     |
| XercesC         | XML parser.                                                                                                                              | X         | X          | X     |
                                                                                                                                                                        
**Conference server only dependencies:**
                                                                                                                                                                        
| Dependency      | Description                                                                                                                              | Mandatory | prepare.py | CMake |
| :---            | :---                                                                                                                                     | :---:     | :---:      | :---: |
| BelleSip        | SIP stack.                                                                                                                               | X         |            | X     |
| LibLinphone++   | SIP user agent C++ library.                                                                                                              | X         |            | X     |


# Compilation

## Required build tools

- C and C++ compiler. GCC and Clang are supported as long as they are recent enough for building C++14 code.
- CMake >= 3.2
- Autotools suite: autoconf, automake, libtool
- make or Ninja
- patch command
- Python >= 3
- Doxygen
- Git


## Building Flexisip with ./prepare.py tool (recommended)

*./prepare.py* allows to build Flexisip and all the required dependencies, so that few dependencies need to be
installed by the user. To use it, just type the following command:

```bash
./prepare.py <build_options>
make -j<njobs>
```

To have the list of all supported options, you may invoke *./prepare.py* with *-lf* options:

```bash
./prepare.py -lf
```

For instance, the following line allows to build Flexisip with the same features than our packages
for CentOS and Debian:

```bash
./prepare.py -DENABLE_CONFERENCE=ON -DENABLE_JWE_AUTH_PLUGIN=ON -DENABLE_EXTERNAL_AUTH_PLUGIN=ON -DENABLE_PRESENCE=ON -DENABLE_PROTOBUF=ON -DENABLE_SNMP=ON -DENABLE_SOCI=ON -DENABLE_TRANSCODER=ON
make -j<njobs>
```

If you need to switch on/off a build option, it is highly recommended to clean the project by using *./prepare.py -c* and configure it again from scratch.


All the built binaries are installed by using *./OUTPUT* directory as prefix.


## Building Flexisip with CMake (recommended for package maintainer)

Before configuring, you need to install all the dependencies marked as *CMake* in [“Dependencies”](#dependencies) section.

Then, create a build directory and configure the project:

```bash
mkdir ./work
cmake -S . -B ./work -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DSYSCONF_INSTALL_DIR=/etc
make -C ./work -j<njobs>
```

Check *CMakeLists.txt* to know the list of the available options and their default value. To change an option, you just need to invoke *CMake* again by specifying the option you need to change only.
For instance, to enable the presence server feature:

```bash
cmake ./work -DENABLE_PRESENCE=ON
make -C ./work -j<njobs>
```

You may also use *ccmake* or *cmake-gui* utilities to configure the project interactively:

```bash
ccmake ./work
make -C ./work -j<njobs>
```

## Building RPM or DEB packages

```bash
./prepare.py flexisip-rpm -DENABLE_CONFERENCE=ON -DENABLE_JWE_AUTH_PLUGIN=ON -DENABLE_EXTERNAL_AUTH_PLUGIN=ON -DENABLE_PRESENCE=ON -DENABLE_PROTOBUF=ON -DENABLE_SNMP=ON -DENABLE_SOCI=ON -DENABLE_TRANSCODER=ON
make -j1 # The build MUST be sequential
```

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
