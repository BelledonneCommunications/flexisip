############################################################################
# CMakeLists.txt
# Copyright (C) 2019 Belledonne Communications, Grenoble France
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

set(HEADER_FILES
	agent.hh
	common.hh
	configmanager.hh
	event.hh
	eventlogs.hh
	forkbasiccontext.hh
	forkcallcontext.hh
	forkmessagecontext.hh
	global.hh
	logmanager.hh
	module-auth.hh
	module-registrar.hh
	module-router.hh
	module.hh
	plugin.hh
	registrardb.hh
	transaction.hh
)

set(FLEXISIP_HEADER_FILES )
foreach(HEADER_FILE ${HEADER_FILES})
	list(APPEND FLEXISIP_HEADER_FILES "${CMAKE_CURRENT_LIST_DIR}/flexisip/${HEADER_FILE}")
endforeach()
set(FLEXISIP_HEADER_FILES ${FLEXISIP_HEADER_FILES} PARENT_SCOPE)

install(FILES ${FLEXISIP_HEADER_FILES}
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/flexisip
	PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
