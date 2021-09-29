############################################################################
# LinphoneSDK.cmake
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

############################################################################
# Add every required Linphone SDK project as subproject
############################################################################

# Global SDK config
set(DISABLE_BC_PACKAGE_SEARCH ON)
set(BCUNIT_TARGETNAME "bcunit")
set(BCTOOLBOX_CMAKE_UTILS_DIR "${CMAKE_CURRENT_BINARY_DIR}/linphone-sdk/bctoolbox")
set(ENABLE_SHARED ON)
set(ENABLE_STATIC OFF)
set(ENABLE_TOOLS OFF)
set(ENABLE_TEST OFF)
set(ENABLE_TESTS OFF)
set(ENABLE_DOC OFF)
set(ENABLE_PACKAGE_SOURCE OFF)

# BCunit specific config
set(ENABLE_AUTOMATED ON)
set(ENABLE_BASIC ON)
set(ENABLE_CONSOLE ON)
set(ENABLE_CURSES OFF)
set(ENABLE_MEMTRACE OFF)
set(ENABLE_DEPRECATED OFF)
add_subdirectory("linphone-sdk/bcunit")

# BcToolbox specific config
set(ENABLE_POLARSSL OFF)
set(ENABLE_MBEDTLS ON)
set(ENABLE_DECAF OFF)
set(ENABLE_TESTS_COMPONENT ${ENABLE_UNIT_TESTS})
add_subdirectory("linphone-sdk/bctoolbox")

# oRTP specific config
set(ENABLE_NTP_TIMESTAMP OFF)
set(ENABLE_PERF OFF)
set(ENABLE_DEBUG_LOGS OFF)
add_subdirectory("linphone-sdk/ortp")

# Belr specific config
add_subdirectory("linphone-sdk/belr")

# Mediastreamer specific config
if(ENABLE_TRANSCODER)
	set(ENABLE_DEBUG_LOGS OFF)
	set(ENABLE_FIXED_POINT "Turn on fixed point computations." OFF)
	set(ENABLE_NON_FREE_CODECS OFF)
	set(ENABLE_PCAP OFF)
	set(ENABLE_RELATIVE_PREFIX OFF)

	set(ENABLE_SRTP ON)
	set(ENABLE_ZRTP ON)

	set(ENABLE_SOUND OFF) # Disable all sound card backends.

	set(ENABLE_G726 OFF)
	set(ENABLE_GSM ON)
	set(ENABLE_BV16 OFF)
	set(ENABLE_OPUS ON)
	set(ENABLE_SPEEX_CODEC ON)
	set(ENABLE_SPEEX_DSP ON)
	set(ENABLE_G729 OFF) # Disable for lisence conformity
	set(ENABLE_G729B_CNG OFF) # Disalbe for lisence conformity
	set(ENABLE_RESAMPLE ON)

	set(ENABLE_VIDEO OFF)
	set(ENABLE_MKV OFF)
	set(ENABLE_JPEG OFF)

	set(DISABLE_SRTP_SEARCH ${INTERNAL_LIBSRTP2})
	add_subdirectory("linphone-sdk/mediastreamer2")
endif()

# Belle-sip specific config
if(ENABLE_PRESENCE OR ENABLE_MDNS OR ENABLE_CONFERENCE OR ENABLE_UNIT_TESTS)
	set(BELLESIP_TARGETNAME "bellesip")
	set(ENABLE_RTP_MAP_ALWAYS_IN_SDP OFF)
	set(ENABLE_TUNNEL OFF)

	# antlr3 settings
	set(ENABLE_64BIT  OFF)
	set(ENABLE_DEBUGGER OFF)

	add_subdirectory("linphone-sdk/belle-sip")
endif()

# Liblinphone specific config
if(ENABLE_CONFERENCE)
	set(DISABLE_SOCI_PACKAGE_SEARCH ON)

	set(ENABLE_ADVANCED_IM ON)
	set(ENABLE_CONSOLE_UI OFF)
	set(ENABLE_CSHARP_WRAPPER OFF)
	set(ENABLE_CXX_WRAPPER YES)
	set(ENABLE_DB_STORAGE YES)
	set(ENABLE_FLEXIAPI OFF)
	set(ENABLE_SWIFT_WRAPPER OFF)
	set(ENABLE_SWIFT_WRAPPER_COMPILATION OFF)
	set(ENABLE_JAZZY_DOC OFF)
	set(ENABLE_DATE OFF)
	set(ENABLE_DEBUG_LOGS OFF)
	set(ENABLE_LIME_X3DH OFF)
	set(ENABLE_JAVA_WRAPPER OFF)
	set(ENABLE_JAVADOC OFF)
	set(ENABLE_LDAP OFF)
	set(ENABLE_LIME OFF)
	set(ENABLE_RELATIVE_PREFIX OFF)
	set(ENABLE_TUNNEL OFF)
	set(ENABLE_TUTORIALS OFF)
	set(ENABLE_UPDATE_CHECK OFF)
	set(ENABLE_VCARD OFF)
	set(ENABLE_VIDEO OFF)
	set(ENABLE_ASSETS OFF)

	set(ENABLE_UNIT_TESTS ${ENABLE_LIBLINPHONE_TESTER}) # override Flexisip ENABLE_UNIT_TESTS option by using a local variable
	if (APPLE)
		set(ENABLE_DAEMON OFF)
	else ()
		set(ENABLE_DAEMON ON)
	endif()
	add_subdirectory("linphone-sdk/liblinphone")
	unset(ENABLE_UNIT_TESTS) # remove the overriding
endif()
