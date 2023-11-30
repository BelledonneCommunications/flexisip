############################################################################
# CMakeLists.txt
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

set(CPACK_PACKAGE_NAME "bc-flexisip")
set(CPACK_PACKAGE_VERSION "${FLEXISIP_FULL_VERSION}")
set(CPACK_PACKAGE_VENDOR "Belledonne Communications SARL")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SIP server suite including proxy server, presence server and IM conference server.")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/description.txt")
set(CPACK_PACKAGE_HOMEPAGE_URL "http://flexisip.org")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

bc_compute_linux_package_version("${FLEXISIP_FULL_VERSION}" version release)
set(extra_dependencies
	"logrotate"
	"python3-google-auth"
	"python3-requests"
)
list(JOIN extra_dependencies ", " extra_dependencies_str)

set(obsolete_packets
	"bc-bctoolbox"
	"bc-bctoolbox-devel"
	"bc-belle-sip"
	"bc-belle-sip-devel"
	"bc-belr"
	"bc-belr-devel"
	"bc-flexisip-external-auth-plugin"
	"bc-flexisip-jwe-auth-plugin"
	"bc-hiredis"
	"bc-hiredis-devel"
	"bc-jose"
	"bc-jose-devel"
	"bc-liblinphone"
	"bc-liblinphone-devel"
	"bc-mediastreamer"
	"bc-mediastreamer-devel"
	"bc-mysql-connector-odbc"
	"bc-ortp"
	"bc-ortp-devel"
	"bc-soci"
	"bc-soci-devel"
	"bc-soci-mysql"
	"bc-soci-mysql-devel"
	"bc-soci-postgresql"
	"bc-soci-postgresql-devel"
	"bc-soci-sqlite3"
	"bc-soci-sqlite3-devel"
	"bc-sofia-sip"
	"bc-sofia-sip-devel"
	"bc-sofia-sip-utils"
	"bc-unixODBC"
)
list(JOIN obsolete_packets ", " obsolete_packets_str)


# Set the SystemD services that should be restarted on package update
set(FLEXISIP_SERVICES "flexisip-proxy flexisip-regevent")
if(ENABLE_PRESENCE)
	string(APPEND FLEXISIP_SERVICES " flexisip-presence")
endif()
if(ENABLE_CONFERENCE)
	string(APPEND FLEXISIP_SERVICES " flexisip-conference")
endif()
if(ENABLE_B2BUA)
	string(APPEND FLEXISIP_SERVICES " flexisip-b2bua")
endif()

# List of files to mark as config files.
# Prevents them from being replaced after a package upgrade or downgrade if their content has been modified.
set(CONFIG_FILES
	"${FLEXISIP_LOGROTATE_INSTALL_LOCATION}"
	"${FLEXISIP_CONFIGURATION_FILE_INSTALL_LOCATION}"
)

#######################################################################################################################
# RedHat/CentOS package
#######################################################################################################################

if("RPM" IN_LIST CPACK_GENERATOR)

	set(CPACK_RPM_PACKAGE_EPOCH "1")
	set(CPACK_RPM_PACKAGE_LICENSE "AGPLv3")
	set(CPACK_RPM_PACKAGE_GROUP "Applications/Communication")
	set(CPACK_RPM_PACKAGE_VERSION "${version}")
	set(CPACK_RPM_PACKAGE_RELEASE "${release}")
	set(CPACK_RPM_PACKAGE_REQUIRES "${extra_dependencies_str}")
	set(CPACK_RPM_PACKAGE_OBSOLETES "${obsolete_packets_str}")
	set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
	set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
	set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
		"/etc/logrotate.d"
		"/lib"
		"/lib/systemd"
		"/lib/systemd/system"
		"/opt/belledonne-communications/include"
	)

	## Enable debuginfo package generation
	set(rpm_debug_install_dir "/usr/src/debug")
	set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX "${rpm_debug_install_dir}/${CPACK_PACKAGE_NAME}")
	set(CPACK_RPM_DEBUGINFO_PACKAGE ON)
	message(STATUS "RPM debuginfo: all occurrences of '${PROJECT_SOURCE_DIR}' will be replaced by "
		"'${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}/src_0' in the binary files."
	)

	# Ensure we use python3.
	set(CPACK_RPM_SPEC_MORE_DEFINE "%global __python %{__python3}")

	### RPM Cpack generator limitation: the length of "${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}/src_0"
	### must not be longer than ${PROJECT_SOURCE_DIR}
	string(LENGTH "${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}" cur_length)

	string(LENGTH "${rpm_debug_install_dir}" min_length)
	math(EXPR min_length "${min_length} + 2")

	string(LENGTH "${PROJECT_SOURCE_DIR}" max_length)
	string(LENGTH "/src_0" suffix_length)
	math(EXPR max_length "${max_length} - ${suffix_length}")

	if(cur_length GREATER max_length)
		message(WARNING "RPM debuginfo: PROJECT_SOURCE_DIR ('${PROJECT_SOURCE_DIR}') must be longer than '${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}/src_0', trying to shrink")
		if(max_length LESS min_length)
			message(FATAL_ERROR "RPM debuginfo: PROJECT_SOURCE_DIR is not long enough to include '${rpm_debug_install_dir}'")
		endif()
		string(SUBSTRING "${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}" 0 ${max_length} CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX)
		message(STATUS "RPM debuginfo: '${PROJECT_SOURCE_DIR}' will be replaced by '${CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX}'/src_0")
	endif()

	## Configure %post, %postun, %preun rpmbuild section
	set(FLEXISIP_LOGDIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/log")
	set(FLEXISIP_B2BUA_DATADIR "${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/flexisip/b2b")
	foreach(secname "post_install" "pre_uninstall" "post_uninstall")
		configure_file("rpm/${secname}.spec.in" "rpm/${secname}.spec" @ONLY)
		string(TOUPPER "${secname}" SECNAME)
		set(CPACK_RPM_${SECNAME}_SCRIPT_FILE "${CMAKE_CURRENT_BINARY_DIR}/rpm/${secname}.spec")
	endforeach()

	## Declare config files
	foreach(conffile ${CONFIG_FILES})
		list(APPEND CPACK_RPM_USER_FILELIST "%config(noreplace) ${conffile}")
	endforeach()

endif()


#######################################################################################################################
# Debian package
#######################################################################################################################

if("DEB" IN_LIST CPACK_GENERATOR)

	# CPackDEB bug: component mode must be on for debsym pacage generation
	set(CPACK_DEB_COMPONENT_INSTALL ON)

	# CPACK_DEBIAN_PACKAGE_NAME must be redefined because its default value is "${CPACK_PACKAGE_NAME}-<component>"
	# when component mode is on.
	set(CPACK_DEBIAN_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
	set(CPACK_DEBIAN_UNSPECIFIED_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
	set(CPACK_DEBIAN_PACKAGE_VERSION "${version}-${release}")
	set(CPACK_DEBIAN_PACKAGE_MAINTAINER "info@belledonne-communications.com")
	set(CPACK_DEBIAN_PACKAGE_SECTION "net")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${extra_dependencies_str}")
	set(CPACK_DEBIAN_PACKAGE_PROVIDES "${obsolete_packets_str}")
	set(CPACK_DEBIAN_PACKAGE_CONFLICTS "${obsolete_packets_str}")
	set(CPACK_DEBIAN_PACKAGE_REPLACES "${obsolete_packets_str}")
	set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
	set(CPACK_DEBIAN_DEBUGINFO_PACKAGE ON)
	set(CPACK_COMPONENTS_ALL "Unspecified")

	# Use Debian convention for package naming
	set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")

	# Generate conffiles control file
	set(conffiles_path "${CMAKE_CURRENT_BINARY_DIR}/deb/conffiles")
	file(WRITE "${conffiles_path}" "")
	foreach(conffile ${CONFIG_FILES})
		file(APPEND "${conffiles_path}" "${conffile}\n")
	endforeach()
	list(APPEND CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${conffiles_path}")

	# Add control scripts
	set(control_files "postinst" "prerm" "postrm")
	foreach(control ${control_files})
		configure_file("deb/${control}.in" "deb/${control}" @ONLY)
		list(APPEND CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_BINARY_DIR}/deb/${control}")
	endforeach()

endif()

#######################################################################################################################

include(CPack)
