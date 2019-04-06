[![pipeline status](https://gitlab.linphone.org/BC/public/flexisip/badges/master/pipeline.svg)](https://gitlab.linphone.org/BC/public/flexisip/commits/master)

Flexisip is a SIP server suite comprising:
 - Flexisip proxy server, a SIP proxy with media-relay built-in.
 - Flexisip presence server, a presence server using resource-lists contained in SUBSCRIBE.

It bests runs on GNU/Linux, but can also be used on MacOS X.
It is released under the AGPLv3 or later. Please understand the terms of AGPLv3 in COPYING before deploying it.

# Documentation

You will find a comprehensive documentation on how to use Flexisip online
here: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/

# Dependencies

Flexisip depends on the following projects, added as submodule in the git repository:
- sofia-sip
- ortp
- bctoolbox
- hiredis (optionaly)

Thesedependencies below are optional, though stronly recommended for a reliable and scalable deployment:
- soci
- protobuf
- netsnmp

Specifically for presence server:
- xsd (>= 4, for old OS on which this version isn't packaged, rpm and deb
  are available here: http://www.codesynthesis.com/products/xsd/download.xhtml)
- pdflatex to generate the documentation in PDF format.
- xercesc3


# Compilation

Flexisip uses cmake as build system, extended by a prepare.py script written in python.
Note that some automake/autoconf scripts and Makefile.am are also present in the source code, however
they are no longer the recommended way for building flexisip, and these files will be removed in mid term.

## GNU/Linux developer build

You can issue ./prepare.py -lf to see all possible build options.
Then use the following to proceed with compilation:
	./prepare.py <build options>
	make


Alternatively, provided that ortp, bctoolbox and sofia-sip dependencies are installed on the system, flexisip's cmake
integration can be used directly, for example:

	cmake . -DCMAKE_INSTALL_PREFIX=/opt/belledonne-communications -DSYSCONF_INSTALL_DIR=/etc
	make

## rpm and deb packages

The "flexisip-rpm" ./prepare.py target can be used to generate rpm packages for flexisip and its dependencies.
"Alien" program is used internaly to convert into debian packages, when this build is run on a debian or debian like linux OS.
The following dependency packages are required (as rpm package name): 
 mbedtls-devel sqlite-devel postgresql-devel rpm-build bison speex-devel

	./prepare.py flexisip-rpm -DENABLE_REDIS=ON -DENABLE_BC_HIREDIS=ON
	make

## Docker

A docker image can be build from sources with command:
	cd docker && make flexisip-build

## Macos X

The cmake scripts of flexisip can be used to develop with Flexisip in Xcode.
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

You can now use -DENABLE_SOCI=ON in your prepare options.

# Configuration


Flexisip needs a configuration file for running correctly.
You can either:
- copy and modify file flexisip.conf.sample to flexisip.conf in directory <prefix>/etc/flexisip
- or issue `flexisip --dump-default all > flexisip.conf` in a terminal
  to generate a configuration file with the default values.

# Developer notes

With sofia-sip, you have the choice between msg_dup and msg_copy,
sip_from_dup and sip_from_copy etc...
The difference isn't well documented in sofia-sip documentation.
However it is important to understand that
*_copy() just makes a copy of the structure, not the strings pointed by it
*_dup() makes a copy of structure plus all included strings inside.
*_copy() versions can be thus dangerous. Use *_dup() in doubt.

