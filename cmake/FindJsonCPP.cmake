############################################################################
# Findjsoncpp.cmake
# Copyright (C) 2010-2024 Belledonne Communications, Grenoble France
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

include(FindPackageHandleStandardArgs)
		
if(INTERNAL_JSONCPP)
    if(NOT TARGET jsoncpp_lib)
        add_subdirectory("${PROJECT_SOURCE_DIR}/linphone-sdk/external/jsoncpp" "${PROJECT_BINARY_DIR}/linphone-sdk/external/jsoncpp")
    endif()
	find_package_handle_standard_args(jsoncpp DEFAULT_MSG)
else()
	find_package(jsoncpp CONFIG)
	if(jsoncpp_FOUND)
	    get_target_property(JSONCPP_INCLUDE_DIR jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
	    find_file(JSON_HEADER_FOUND NAMES "json.h" PATHS "${JSONCPP_INCLUDE_DIR}/json/" NO_CACHE)
	    if(NOT JSON_HEADER_FOUND)
	        # CentOS 7-8 & RockyLinux
	        message(STATUS "Invalid jsoncpp include directory detected [${JSONCPP_INCLUDE_DIR}]. Trying '${JSONCPP_INCLUDE_DIR}/jsoncpp'")
			string(APPEND JSONCPP_INCLUDE_DIR "/jsoncpp")
			find_file(JSON_HEADER_FOUND NAMES "json.h" PATHS "${JSONCPP_INCLUDE_DIR}/json/" NO_CACHE)
			if(NOT JSON_HEADER_FOUND)
				message(FATAL_ERROR "CMake config file for 'jsoncpp' library is invalid. Try -DINTERNAL_JSONCPP=ON")
			endif()
			set_target_properties(jsoncpp_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${JSONCPP_INCLUDE_DIR}")
	    endif()
	else()
		message(STATUS "Searching for jsoncpp in module mode")
		find_path(jsoncpp_INCLUDE_DIR "json/json.h" PATH_SUFFIXES "jsoncpp")
		find_library(jsoncpp_LIBRARIES jsoncpp)

		# Get version number
		if (jsoncpp_INCLUDE_DIR)
			set(version_def_line_regex "^[ \\t]*#[ \\t]*define[ \\t]+JSONCPP_VERSION_STRING[ \\t]+\"([0-9]+\\.[0-9]+\\.[0-9]+)\"[ \\t]*$")
			file(STRINGS "${jsoncpp_INCLUDE_DIR}/json/version.h" version_def_line REGEX "${version_def_line_regex}")
			if (NOT version_def_line)
				message(FATAL_ERROR "Cannot find version number of jsoncpp")
			endif()
			string(REGEX REPLACE "${version_def_line_regex}" "\\1" version "${version_def_line}")
		endif()
		
		find_package_handle_standard_args(jsoncpp
			REQUIRED_VARS jsoncpp_INCLUDE_DIR jsoncpp_LIBRARIES
			VERSION_VAR version
		)
		
		mark_as_advanced(jsoncpp_LIBRARIES jsoncpp_INCLUDE_DIR)
		
		if(jsoncpp_FOUND)
			add_library(jsoncpp_lib SHARED IMPORTED)
			set_target_properties(jsoncpp_lib
				PROPERTIES
					IMPORTED_LOCATION ${jsoncpp_LIBRARIES}
					INTERFACE_INCLUDE_DIRECTORIES ${jsoncpp_INCLUDE_DIR}
			)
		endif()
	endif()
endif()

# TODO Remove the following bloc when (if) the SDK decides to use lowercase `jsoncpp` in its `find_package`
# https://linphone.atlassian.net/browse/SDK-184
if(TARGET jsoncpp_lib)
	set(JsonCPP_TARGET jsoncpp_lib)
else()
	set(JsonCPP_TARGET jsoncpp_static)
endif()
set(JsonCPP_FOUND ${jsoncpp_FOUND})
