############################################################################
# CMakeLists.txt
# Copyright (C) 2017-2018  Belledonne Communications, Grenoble France
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
set(CPACK_PACKAGE_VENDOR "Belledonne Communications SARL")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "SIP server suite comprising proxy, presence, and IM conference server.")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/description.txt")
set(CPACK_PACKAGE_HOMEPAGE_URL "http://flexisip.org")
set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/belledonne-communications")
set(CPACK_GENERATOR "RPM")

bc_compute_linux_package_version("${FLEXISIP_FULL_VERSION}" version release)

set(CPACK_RPM_PACKAGE_EPOCH "1")
set(CPACK_RPM_PACKAGE_LICENSE "AGPLv3")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Communication")
set(CPACK_RPM_PACKAGE_RELEASE "${release}")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
	"/opt/belledonne-communications/include"
)
set(CPACK_RPM_FILE_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}.${CMAKE_HOST_SYSTEM_PROCESSOR}.rpm")

include(CPack)
