############################################################################
# ExternalDependencies.cmake
# Copyright (C) 2010-2023  Belledonne Communications, Grenoble France
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

############################################################################
# Add some external dependencies as subproject
############################################################################

# Configure and add SofiaSip
function(add_sofiasip) # Use function of override variable without propagating the change afterwards
	set(ENABLE_UNIT_TESTS OFF)
	add_subdirectory("submodules/externals/sofia-sip")
endfunction()
add_sofiasip()

# Add libhiredis
if(ENABLE_REDIS AND INTERNAL_LIBHIREDIS)
	function(add_hiredis)
		set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # Prevent project from overriding the options set at this level
		set(ENABLE_SSL ON)
		set(DISABLE_TESTS OFF)
		set(ENABLE_SSL_TESTS OFF)
		set(ENABLE_ASYNC_TESTS OFF)

		add_subdirectory("submodules/externals/hiredis")
	endfunction()
	add_hiredis()
endif()