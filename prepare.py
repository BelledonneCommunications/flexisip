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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

import os
import platform
import sys
from logging import error, warning, info
sys.dont_write_bytecode = True
sys.path.insert(0, 'submodules/cmake-builder')
try:
    import prepare
except Exception as e:
    error(
        "Could not find prepare module: {}, probably missing submodules/cmake-builder? Try running:\n"
        "git submodule sync && git submodule update --init --recursive".format(e))
    exit(1)


class FlexisipRpmTarget(prepare.Target):

    def __init__(self):
        prepare.Target.__init__(self, 'flexisip-rpm')
        current_path = os.path.dirname(os.path.realpath(__file__))
        self.required_build_platforms = ['Linux', 'Darwin']
        self.config_file = 'configs/config-flexisip-rpm.cmake'
        self.external_source_path = os.path.join(current_path, 'submodules')
        self.additional_args = [ '-DLINPHONE_BUILDER_TARGET=flexisip', '-DLINPHONE_BUILDER_TOP_DIR=' + current_path ]

class FlexisipTarget(prepare.Target):

    def __init__(self):
        prepare.Target.__init__(self, 'flexisip')
        current_path = os.path.dirname(os.path.realpath(__file__))
        self.required_build_platforms = ['Linux', 'Darwin']
        self.config_file = 'configs/config-flexisip.cmake'
        self.external_source_path = os.path.join(current_path, 'submodules')
        self.additional_args = [ '-DLINPHONE_BUILDER_TARGET=flexisip', '-DLINPHONE_BUILDER_TOP_DIR=' + current_path ]


flexisip_targets = {
    'flexisip': FlexisipTarget(),
    'flexisip-rpm': FlexisipRpmTarget()
}

class FlexisipPreparator(prepare.Preparator):

    def __init__(self, targets=flexisip_targets, default_targets=['flexisip']):
        prepare.Preparator.__init__(self, targets, default_targets)
        self.veryclean = True

    def clean(self):
        prepare.Preparator.clean(self)
        if os.path.isfile('Makefile'):
            os.remove('Makefile')
        if os.path.isdir('WORK') and not os.listdir('WORK'):
            os.rmdir('WORK')
        if os.path.isdir('OUTPUT') and not os.listdir('OUTPUT'):
            os.rmdir('OUTPUT')
        if os.path.isfile('submodules/externals/sofia-sip/configure'):
            os.system('cd submodules/externals/sofia-sip/ && make distclean')

    def generate_makefile(self, generator, project_file=''):
        targets = self.args.target
        targets_str = ""
        for target in targets:
            targets_str += """
{target}: {target}-build

{target}-build:
\t{generator} WORK/{target}/cmake/{project_file}
\t@echo "Done"
""".format(target=target, generator=generator, project_file=project_file)
        makefile = """
targets={targets}

.PHONY: all

all: build

build: $(addsuffix -build, $(targets))

{targets_str}

help-prepare-options:
\t@echo "prepare.py was previously executed with the following options:"
\t@echo "   {options}"

help: help-prepare-options
\t@echo ""
\t@echo "(please read the README.md file first)"
\t@echo ""
\t@echo "Available targets: {targets}"
\t@echo ""
""".format(targets=' '.join(targets), targets_str=targets_str, options=' '.join(sys.argv), generator=generator)
        f = open('Makefile', 'w')
        f.write(makefile)
        f.close()



def main(argv=None):
    preparator = FlexisipPreparator()
    preparator.parse_args()
    if preparator.check_environment(submodule_directory_to_check="submodules/belle-sip/src") != 0:
        preparator.show_environment_errors()
        return 1
    return preparator.run()

if __name__ == "__main__":
    sys.exit(main())
