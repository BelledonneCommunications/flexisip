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

Flexisip depends on the projects below.

**mandatory** marked dependencies are necessary for building a minimal binary of the required server whereas **opional** marked ones may be skipped if the
according feature has been disabled while configuring the source code.

**tier** marked dependencies are projects which aren't developped by Belledonne Communications and must be installed on the build machine before configuring the
source code of Flexisip, execept if they are tagged as **submodule**.

**submodule** marked dependencies are projects (tier projects for the most), which the Git repository has been added as submodule of Flexisip project, and thus don't need to be installed on
the build machine if the *./prepare.py* utilities is used to configure source code. However, package maintainers will need to install the dependencies since
common package building tools use to build projects seperately.

**linphone-sdk** dependecies are projects which are developped by Belledonne Communications for the sake of Linphone client. These projects are also submodules of Flexisip Git repository, so
they may be viewed as **submodule** projects.

- Belledonne Communicaitons maintained SofiaSip project. [See GitLab repository](https://gitlab.linphone.org/BC/public/external/sofia-sip) **[submodule,mandatory]**
- oRTP: stack RTP used for media relay feauture. **[linphone-sdk,optional]**
- bctoolbox: several basic utilities. **[linphone-sdk,mandatory]**
- belr: generic parser using ABNF grammar, used for user file parsing. **[linphone-sdk,mandatory]**
- openSSL: TLS stack. **[tier,mandatory]**
- hiredis: Redis DB client library, used for Registrar DB and communications between Flexisip instances of a same cluster. **[tier,mandatory]**
- mediastreamer: media engine used for transcoding feature. **[linphone-sdk,optional]**
- protobuf: needed for migration from legacy registrar database format. **[tier,optional]**
- belle-sip: mDNS support. **[linphone-sdk,optional]**
- soci: SQL dadabase client, used for user database reading and event logs. **[submodule,optional]**
- netsnmp: SNMP library, used for SNMP support. **[tier,optional]**
- pdflatex: to generate the reference documentation as PDF. **[tier,optional]** 

Specifically for presence server:
- belle-sip: SIP stack. **[linphone-sdk,mandatory]**
- xsd(=4.0.0): W3C XML Schema to C++ data binding compiler. **[tier,submodule,mandatory]**
- xercesc: XML parser. **[tier,submodule,mandatory]**

Specifically for conference server:
- belle-sip: SIP stack. **[linphone-sdk,mandatory]**
- liblinphone++: SIP user agent library. **[linphone-sdk,mandatory]**


# Compilation

Flexisip uses cmake as build system, extended by a prepare.py script written in Python.

## GNU/Linux developer build

You can issue ./prepare.py -lf to see all possible build options.
Then, use the following to proceed with compilation:
	./prepare.py <build options>
	make

Alternatively, should all the dependencies listed above be installed on the system, Flexisip's CMake scripts
can be used directly. For example:

	cmake . -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DSYSCONF_INSTALL_DIR=/etc
	make

## rpm and deb packages

The `flexisip-rpm` prepare.py target can be used to generate RPM packages for Flexisip and its dependencies.
_Alien_ program is used internaly to convert RPMs into Debian packages when this build is run on a Debian or Debian-like GNU/Linux distribution.
The following dependency packages are required (as rpm package name): 
 mbedtls-devel sqlite-devel postgresql-devel rpm-build bison speex-devel

	./prepare.py flexisip-rpm -DENABLE_REDIS=ON -DENABLE_BC_HIREDIS=ON
	make

## Docker

A docker image can be build from sources with command:

	docker build -t flexisip --build-arg=njobs=<njobs> -f docker/flex-from-src .

## Macos X (outdated)

The CMake scripts of Flexisip can be used to develop with Flexisip in Xcode.
You need to run:
- `./prepare.py -G Xcode flexisip \
	-DENABLE_REDIS=NO \
	-DEP_sofiasip_CONFIGURE_OPTIONS=PKG_CONFIG_PATH=/opt/local/lib/pkgconfig/ `
- `xcodebuild -project WORK/flexisip/cmake/Project.xcodeproj/ `
- `open WORK/flexisip/Build/flexisip/flexisip.xcodeproj`

The soci dependency is not easy to install on MacOS. If you need it, you can use these tips, based on "brew" system:

You need to install and unlink mysql :
brew install mysql
brew unlink mysql
Then install mysql-connector-c
brew install mysql-connector-c
And finally install soci with mysql
brew install soci --with-mysql

You can now use `-DENABLE_SOCI=ON` in your prepare options.

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
