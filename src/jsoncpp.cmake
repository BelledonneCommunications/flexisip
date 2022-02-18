# SPDX-License-Identifier: GPL-3.0-or-later

if(INTERNAL_JSONCPP)
	if(NOT TARGET jsoncpp_lib)
		add_subdirectory(${PROJECT_SOURCE_DIR}/linphone-sdk/external/jsoncpp ${CMAKE_CURRENT_BINARY_DIR}/jsoncpp)
	endif()
else()
	find_package(jsoncpp)
	if(NOT jsoncpp_FOUND)
		message(FATAL_ERROR "Could NOT find jsoncpp. If your system cannot provide it, try to build the vendored version with -DINTERNAL_JSONCPP=YES.")
	endif()

	get_target_property(JSONCPP_INCLUDE_DIR jsoncpp_lib INTERFACE_INCLUDE_DIRECTORIES)
	find_file(JSON_HEADER_FOUND "json.h" ${JSONCPP_INCLUDE_DIR}/json/)
	if(NOT JSON_HEADER_FOUND)
		# CentOS 7-8 & RockyLinux
		message(FATAL_ERROR "Invalid jsoncpp include directory detected. We believe this is an issue with your distribution's packaging. Try to build the vendored version with -DINTERNAL_JSONCPP=YES.")
	endif()
endif()
