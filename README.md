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

**Common and proxy dependencies:**

| Dependency    | Description                                                                                                                              | Mandatory | Tier  | Submodule | Linphone-sdk |
| :---          | :---                                                                                                                                     | :---:     | :---: | :---:     | :---:        |
| BcSofiaSip    | Belledonne Communications maintained SofiaSip project. [See GitLab repository](https://gitlab.linphone.org/BC/public/external/sofia-sip) | X         |       | X         |              |
| oRTP          | RTP stack used for media relay feature.                                                                                                  |           |       |           | X            |
| BcToolbox     | Several basic utilities.                                                                                                                 | X         |       |           | X            |
| BelR          | Generic parser using ABNF grammar, used for user file parsing.                                                                           | X         |       |           | X            |
| OpenSSL       | TLS stack.                                                                                                                               | X         | X     |           |              |
| Hiredis       | Redis DB client library, used for Registrar DB and communications between Flexisip instances of a same cluster.                          | X         | X     |           |              |
| LibNgHttp2    | HTTP2 stack.                                                                                                                             | X         | X     |           |              |
| Mediastreamer | Media engine used for transcoding feature.                                                                                               |           |       |           | X            |
| Protobuf      | Needed for migration from legacy registrar database format.                                                                              |           | X     |           |              |
| BelleSip      | mDNS support.                                                                                                                            |           |       |           | X            |
| Soci          | SQL database client, used for user database reading and event logs.                                                                      | X         | X     | X         |              |
| Soci-sqlite3  | Soci connector for SQLit3.                                                                                                               | X         | X     | X         |              |
| Soci-mysql    | Soci connector for MySQL.                                                                                                                | X         | X     | X         |              |
| NetSNMP       | SNMP library, used for SNMP support.                                                                                                     |           | X     |           |              |
| pdflatex      | To generate the reference documentation as PDF.                                                                                          |           | X     |           |              |

**Presence server only dependencies:**

- belle-sip: SIP stack. **[linphone-sdk,mandatory]**
- xsd(=4.0.0): W3C XML Schema to C++ data binding compiler. **[tier,mandatory]**
- xercesc: XML parser. **[tier,mandatory]**

**Conference server only dependencies:**

- belle-sip: SIP stack. **[linphone-sdk,mandatory]**
- liblinphone++: SIP user agent library. **[linphone-sdk,mandatory]**

---

**mandatory** marked dependencies are necessary for building a minimal binary of the required server whereas **optional** marked ones may be skipped if the
according feature has been disabled while configuring the source code.

**tier** marked dependencies are projects which aren't developed by Belledonne Communications and must be installed on the build machine before configuring the
source code of Flexisip, except if they are tagged as **submodule**.

**submodule** marked dependencies are projects (tier projects for the most), which the Git repository has been added as submodule of Flexisip project, and thus don't need to be installed on
the build machine if the *./prepare.py* utilities is used to configure source code. However, package maintainers will need to install the dependencies since
common package building tools use to build projects separately.

**linphone-sdk** dependencies are projects which are developed by Belledonne Communications for the sake of Linphone client. These projects are also submodules of Flexisip Git repository, so
they may be viewed as **submodule** projects.


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

## GNU/Linux developer build

You can issue ./prepare.py -lf to see all possible build options.
Then, use the following to proceed with compilation:

```bash
./prepare.py <build options>
make
```

Alternatively, should all the dependencies listed above be installed on the system, Flexisip's CMake scripts
can be used directly. For example:

```bash
cmake . -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DSYSCONF_INSTALL_DIR=/etc
make
```

## rpm and deb packages

The `flexisip-rpm` prepare.py target can be used to generate RPM packages for Flexisip and its dependencies.
_Alien_ program is used internaly to convert RPMs into Debian packages when this build is run on a Debian or Debian-like GNU/Linux distribution.
The following dependency packages are required (as rpm package name): 
 mbedtls-devel sqlite-devel postgresql-devel rpm-build bison speex-devel

```bash
./prepare.py flexisip-rpm -DENABLE_REDIS=ON -DENABLE_BC_HIREDIS=ON
make
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
