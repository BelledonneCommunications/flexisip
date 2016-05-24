#!/usr/bin/env python

############################################################################
# prepare.py
# Copyright (C) 2015  Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
############################################################################

import argparse
import os
import platform
import sys
from logging import error, warning, info, INFO, basicConfig
from subprocess import Popen
from distutils.spawn import find_executable
sys.dont_write_bytecode = True
sys.path.insert(0, 'submodules/cmake-builder')
try:
    import prepare
except Exception as e:
    error(
        "Could not find prepare module: {}, probably missing submodules/cmake-builder? Try running:\ngit submodule update --init --recursive".format(e))
    exit(1)

class FlexisipRpmTarget(prepare.Target):

    def __init__(self):
        prepare.Target.__init__(self, 'flexisip-rpm')
        current_path = os.path.dirname(os.path.realpath(__file__))
        self.required_build_platforms = ['Linux', 'Darwin']
        self.config_file = 'configs/config-flexisip-rpm.cmake'
        self.additional_args = ['-DLINPHONE_BUILDER_TARGET=flexisip',
                        '-DCMAKE_INSTALL_MESSAGE=LAZY',
                        '-DLINPHONE_BUILDER_TOP_DIR=' + current_path,
                        '-DLINPHONE_BUILDER_EXTERNAL_SOURCE_PATH=' + current_path + '/submodules'
    ]

class FlexisipTarget(prepare.Target):

    def __init__(self):
        prepare.Target.__init__(self, '')
        current_path = os.path.dirname(os.path.realpath(__file__))
        self.required_build_platforms = ['Linux', 'Darwin']
        self.config_file = 'configs/config-flexisip.cmake'
        self.additional_args = [
            '-DLINPHONE_BUILDER_TARGET=flexisip',
            '-DCMAKE_INSTALL_MESSAGE=LAZY',
            '-DLINPHONE_BUILDER_TOP_DIR=' + current_path,
            '-DLINPHONE_BUILDER_EXTERNAL_SOURCE_PATH=' + current_path + '/submodules'
        ]


def check_is_installed(binary, prog='it', warn=True):
    if not find_executable(binary):
        if warn:
            error("Could not find {}. Please install {}.".format(binary, prog))
        return False
    return True


def check_tools():
    ret = 0

    #at least FFmpeg requires no whitespace in sources path...
    if " " in os.path.dirname(os.path.realpath(__file__)):
        error("Invalid location: path should not contain any spaces.")
        ret = 1

    ret |= not check_is_installed('cmake')

    if not os.path.isdir("submodules/mediastreamer2/src") or not os.path.isdir("submodules/ortp/src"):
        error("Missing some git submodules. Did you run:\n\tgit submodule update --init --recursive")
        ret = 1

    return ret


def generate_makefile(generator, work_dir):
    makefile = """
.PHONY: all

all:
\t{generator} {work_dir}

help-prepare-options:
\t@echo "prepare.py was previously executed with the following options:"
\t@echo "   {options}"

help: help-prepare-options
\t@echo ""
\t@echo "(please read the README.md file first)"
\t@echo ""
\t@echo "Available targets:"
\t@echo ""
\t@echo "   * all: normal build"
\t@echo ""
""".format(options=' '.join(sys.argv), generator=generator, work_dir=work_dir)
    f = open('Makefile', 'w')
    f.write(makefile)
    f.close()
targets = {}
targets['flexisip'] = FlexisipTarget()
targets['flexisip-rpm'] = FlexisipRpmTarget()
target_names = sorted(targets.keys())

def main(argv=None):
    basicConfig(format="%(levelname)s: %(message)s", level=INFO)

    if argv is None:
        argv = sys.argv
    argparser = argparse.ArgumentParser(
        description="Prepare build of Flexisip and its dependencies.")
    argparser.add_argument(
        '-c', '--clean', help="Clean a previous build instead of preparing a build.", action='store_true')
    argparser.add_argument(
        '-C', '--veryclean', help="Clean a previous build instead of preparing a build (also deleting the install prefix).", action='store_true')
    argparser.add_argument(
        '-d', '--debug', help="Prepare a debug build, eg. add debug symbols and use no optimizations.", action='store_true')
    argparser.add_argument(
        '-f', '--force', help="Force preparation, even if working directory already exist.", action='store_true')
    argparser.add_argument(
        '-G', '--generator', help="CMake build system generator (default: Unix Makefiles, use cmake -h to get the complete list).", default='Unix Makefiles', dest='generator')
    argparser.add_argument(
        '-L', '--list-cmake-variables', help="List non-advanced CMake cache variables.", action='store_true', dest='list_cmake_variables')
    argparser.add_argument('target', choices=target_names, help="The target to build.", default='flexisip')

    args, additional_args = argparser.parse_known_args()

    additional_args += ["-G", args.generator]
    #additional_args += ["-DLINPHONE_BUILDER_GROUP_EXTERNAL_SOURCE_PATH_BUILDERS=YES"]

    if check_tools() != 0:
        return 1
    target = targets[args.target]

    if args.clean or args.veryclean:
        if args.veryclean:
            target.veryclean()
        else:
            target.clean()
        if os.path.isfile('Makefile'):
            os.remove('Makefile')
    else:
        retcode = prepare.run(target, args.debug, False, args.list_cmake_variables, args.force, additional_args)
        if retcode != 0:
            if retcode == 51:
                Popen("make help-prepare-options".split(" "))
                retcode = 0
            return retcode
        # only generated makefile if we are using Ninja or Makefile
        if args.generator.endswith('Ninja'):
            if not check_is_installed("ninja", "it"):
                return 1
            generate_makefile('ninja -C', target.work_dir + "/cmake")
            info("You can now run 'make' to build.")
        elif args.generator.endswith("Unix Makefiles"):
            generate_makefile('$(MAKE) -C', target.work_dir + "/cmake")
            info("You can now run 'make' to build.")
        elif args.generator == "Xcode":
            info("You can now open Xcode project with: open WORK/cmake/Project.xcodeproj")
        else:
            warning("Not generating meta-makefile for generator {}.".format(args.generator))

    return 0

if __name__ == "__main__":
    sys.exit(main())
