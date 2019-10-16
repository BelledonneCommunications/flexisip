############################################################################
# gitversion.cmake
# Copyright (C) 2014  Belledonne Communications, Grenoble France
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

macro(execute_git GIT_OUTPUT_VARIABLE)
	set(_subcommand_list "${ARGN}")
	execute_process(
		COMMAND ${GIT_EXECUTABLE} ${_subcommand_list}
		WORKING_DIRECTORY ${WORK_DIR}
		OUTPUT_VARIABLE ${GIT_OUTPUT_VARIABLE}
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)
endmacro()

if(GIT_EXECUTABLE)
	execute_git(GIT_DESCRIBE describe)
	execute_git(GIT_REVISION rev-parse HEAD)
	execute_git(GIT_TAG describe --abbrev=0)
else()
	set(GIT_DESCRIBE)
	set(GIT_REVISION)
	set(GIT_TAG)
endif()

if(GIT_DESCRIBE)
	set(GIT_VERSION "${GIT_DESCRIBE}")
	configure_file("${WORK_DIR}/gitversion.h.in" "${OUTPUT_DIR}/flexisip-version.h" @ONLY)
elseif(GIT_REVISION)
	set(GIT_VERSION "${FLEXISIP_VERSION}_${GIT_REVISION}")
	configure_file("${WORK_DIR}/gitversion.h.in" "${OUTPUT_DIR}/flexisip-version.h" @ONLY)
elseif(NOT EXISTS "${OUTPUT_DIR}/flexisip-version.h")
	file(WRITE "${OUTPUT_DIR}/flexisip-version.h" "")
endif()
