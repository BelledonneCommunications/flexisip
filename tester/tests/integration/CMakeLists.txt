# ###########################################################################
# CMakeLists.txt
# Copyright (C) 2010-2026 Belledonne Communications, Grenoble France
#
# ###########################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# ###########################################################################

target_sources(flexisip_tester PRIVATE
	call-tester.cc
	domotic-tester.cc
)

if(ENABLE_B2BUA)
	target_sources(flexisip_tester PRIVATE
		b2bua/call-bridging-tester.cc
		b2bua/call-transfer/attended-call-transfer-tester.cc
		b2bua/call-transfer/blind-call-transfer-tester.cc
		b2bua/call-transfer/call-transfer-commons.cc b2bua/call-transfer/call-transfer-commons.hh
		b2bua/mwi-tester.cc
		b2bua/utils.hh
	)
endif()

if(ENABLE_VOICEMAIL)
	target_sources(flexisip_tester PRIVATE
        voicemail/voicemail-server-tester.cc
	)
endif()