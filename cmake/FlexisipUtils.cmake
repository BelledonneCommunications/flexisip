############################################################################
# FlexisipUtils.cmake
# Copyright (C) 2010-2021  Belledonne Communications, Grenoble France
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

# Add the 'ENABLE_CCACHE' option that allows to find the ccache
# executable on the system to use it as launcher for the C/C++
# compiler.
#
# Parameter:
# * default[in]: default value of ENABLE_CCACHE option. Must be a boolean.
macro(add_ccache_option default)
	option(ENABLE_CCACHE "Use CCache to accelerate the build" ${default})
	if(ENABLE_CCACHE)
		find_program(CCACHE_EXECUTABLE "ccache")
		if(CCACHE_EXECUTABLE)
			message(STATUS "Using '${CCACHE_EXECUTABLE}' as C/C++ compiler launcher")
			set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}")
			set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_EXECUTABLE}")
		endif()
	endif()
endmacro()
