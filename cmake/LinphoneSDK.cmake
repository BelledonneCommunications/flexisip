############################################################################
# LinphoneSDK.cmake
# Copyright (C) 2010-2023 Belledonne Communications, Grenoble France
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
# Add Linphone SDK project as subproject
############################################################################

function(add_linphonesdk)
	if(ENABLE_TRANSCODER OR ENABLE_CONFERENCE OR ENABLE_B2BUA)
		set(BUILD_MEDIASTREAMER2 ON)
		set(ENABLE_ZRTP ON)
	else()
		set(BUILD_MEDIASTREAMER2 OFF)
		set(ENABLE_ZRTP OFF)
	endif()

	set(BUILD_SOCI ${SOCI_REQUIRED})
	if(BUILD_SOCI)
		set(BUILD_SOCI_BACKENDS "mysql;sqlite3")
		if(ENABLE_SOCI_POSTGRESQL_BACKEND)
			string(APPEND BUILD_SOCI_BACKENDS ";postgresql")
		endif()
	endif()

	if(ENABLE_PRESENCE OR ENABLE_MDNS OR ENABLE_CONFERENCE OR ENABLE_UNIT_TESTS)
		set(BUILD_BELLESIP ON)
	endif()

	set(BUILD_LIBLINPHONE ${LIBLINPHONE_REQUIRED})

	# # Global SDK config
	set(ENABLE_DOC OFF)
	set(ENABLE_PACKAGE_SOURCE OFF)
	set(ENABLE_STRICT ${ENABLE_STRICT_LINPHONESDK})
	set(ENABLE_TESTS_COMPONENT ON)
	set(ENABLE_TOOLS OFF)
	set(ENABLE_UNIT_TESTS ${ENABLE_LIBLINPHONE_TESTER})
	set(ENABLE_SANITIZER ${ENABLE_SANITIZERS})

	# Global features activation
	set(BUILD_GSM OFF)
	set(BUILD_JSONCPP ${INTERNAL_JSONCPP})
	set(BUILD_AOM OFF)
	set(BUILD_DAV1D OFF)
	set(BUILD_LIBVPX OFF)
	set(BUILD_LIBXML2 OFF)
	set(BUILD_MBEDTLS_WITH_FATAL_WARNINGS OFF)
	set(BUILD_OPUS OFF)
	set(BUILD_SPEEX OFF)
	set(BUILD_SQLITE3 OFF)
	set(BUILD_XERCESC OFF)
	set(BUILD_ZLIB OFF)
	set(ENABLE_ADVANCED_IM ON)
	set(ENABLE_AMRNB OFF)
	set(ENABLE_AMRWB OFF)
	set(ENABLE_ASSETS OFF)
	set(ENABLE_BV16 OFF)
	set(ENABLE_CODEC2 OFF)
	set(ENABLE_CSHARP_WRAPPER OFF)
	set(ENABLE_CXX_WRAPPER ${BUILD_LIBLINPHONE})
	set(ENABLE_DB_STORAGE ON)
	set(ENABLE_DECAF ON)
	set(ENABLE_FFMPEG OFF)
	set(ENABLE_FLEXIAPI OFF)
	set(ENABLE_G726 OFF)
	set(ENABLE_G729 ${ENABLE_G729})
	set(ENABLE_G729B_CNG OFF) # Disabled for license conformity
	set(ENABLE_GSM ON)
	set(ENABLE_ILBC OFF)
	set(ENABLE_ISAC OFF)
	set(ENABLE_JAVA_WRAPPER OFF)
	set(ENABLE_JAZZY_DOC OFF)
	set(ENABLE_JPEG OFF)
	set(ENABLE_LDAP OFF)
	set(ENABLE_LIBYUV OFF)
	set(ENABLE_LIME OFF)
	set(ENABLE_LIME_X3DH ${BUILD_LIBLINPHONE})

	# ENABLE_MBEDTLS must be a cache variable because this option is declared by
	# libsrtp2 project as cache variable instead of using option() command. That avoid Flexisip
	# to masquerade this variable by using CMP0077 new behavior.
	set(ENABLE_MBEDTLS ON CACHE BOOL "Enable MbedTLS support." FORCE)
	mark_as_advanced(ENABLE_MBEDTLS)

	set(ENABLE_MKV OFF)
	set(ENABLE_NON_FREE_FEATURES OFF)
	set(ENABLE_OPENH264 OFF)
	set(ENABLE_OPUS ON)
	set(ENABLE_PQCRYPTO OFF)
	set(ENABLE_QRCODE OFF)
	set(ENABLE_RELATIVE_PREFIX OFF)
	set(ENABLE_SILK OFF)
	set(ENABLE_SPEEX_CODEC ON)
	set(ENABLE_SPEEX_DSP ON)
	set(ENABLE_SRTP ON)
	set(ENABLE_SWIFT_WRAPPER OFF)
	set(ENABLE_SWIFT_WRAPPER_COMPILATION OFF)
	set(ENABLE_THEORA OFF)
	set(ENABLE_TUNNEL OFF)
	set(ENABLE_VCARD OFF)
	set(ENABLE_VIDEO ON)
	set(ENABLE_VPX ${BUILD_MEDIASTREAMER2})
	set(ENABLE_AV1 OFF)
	set(ENABLE_WEBRTC_AEC OFF)
	set(ENABLE_WEBRTC_VAD OFF)

	set(BUILD_LIBSRTP2 ${INTERNAL_LIBSRTP2})
	set(BUILD_MBEDTLS ${INTERNAL_MBEDTLS})

	# BcToolbox specific config
	set(ENABLE_DEFAULT_LOG_HANDLER OFF)

	# BZRTP specific config
	set(ENABLE_ZIDCACHE ${ENABLE_ZRTP})
	set(ENABLE_EXPORTEDKEY_V1_0_RETROCOMPATIBILITY OFF)
	set(ENABLE_GOCLEAR ON)
	set(ENABLE_PQCRYPTO OFF)

	if(BUILD_MEDIASTREAMER2)
		# Mediastreamer specific config
		set(ENABLE_FIXED_POINT OFF)
		set(ENABLE_PCAP OFF)
		set(ENABLE_SOUND OFF) # Disable all sound card backends.
		set(ENABLE_V4L OFF) # Disable video capture
		# Disable video rendering
		set(ENABLE_GL OFF)
		set(ENABLE_GLX OFF)
		set(ENABLE_SDL OFF)
		set(ENABLE_X11 OFF)
		set(ENABLE_XV OFF)
		set(ENABLE_RESAMPLE ON)
	endif()

	if(BUILD_BELLESIP)
		# Belle-sip specific config
		set(ENABLE_RTP_MAP_ALWAYS_IN_SDP OFF)
	endif()

	if(ENABLE_LIME_X3DH)
		# Lime specific config
		set(ENABLE_CURVE25519 YES)
		set(ENABLE_CURVE448 YES)
		set(ENABLE_PROFILING NO)
		set(ENABLE_C_INTERFACE NO)
		set(ENABLE_JNI NO)
	endif()

	if(BUILD_LIBLINPHONE)
		# Liblinphone specific config
		set(ENABLE_CONSOLE_UI OFF)
		set(ENABLE_DATE OFF)
		set(ENABLE_JAVADOC OFF)
		set(ENABLE_TUTORIALS OFF)
		set(ENABLE_UPDATE_CHECK OFF)
		if(APPLE)
			set(ENABLE_DAEMON OFF)
		else()
			set(ENABLE_DAEMON ON)
		endif()
	endif()

	if(ENABLE_G729)
		set(ENABLE_GPL_THIRD_PARTIES ON)
	endif()

	set(LINPHONESDK_BUILD_TYPE "Flexisip")

	add_subdirectory("linphone-sdk")
endfunction()

add_linphonesdk()