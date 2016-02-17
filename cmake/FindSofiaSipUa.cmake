############################################################################
# FindSofiaSipUa.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
############################################################################
#
# - Find the sofia-sip include file and library
#
#  SOFIA_SIP_UA_FOUND - system has sofia-sip
#  SOFIA_SIP_UA_INCLUDE_DIRS - the sofia-sip include directory
#  SOFIA_SIP_UA_LIBRARIES - The libraries needed to use sofia-sip
#  SOFIA_SIP_UA_CPPFLAGS - The cflags needed to use sofia-sip


set(_SOFIA_SIP_UA_ROOT_PATHS
  ${WITH_SOFIA_SIP_UA}
  ${CMAKE_INSTALL_PREFIX}
)

find_path(SOFIA_SIP_UA_INCLUDE_DIRS
  NAMES sofia-sip/sip.h
  HINTS _SOFIA_SIP_UA_ROOT_PATHS
  PATH_SUFFIXES include/sofia-sip-1.13 include/sofia-sip-1.12
)

if(SOFIA_SIP_UA_INCLUDE_DIRS)
  set(HAVE_SOFIA_SIP_UA_SOFIA_SIP_UA_H 1)
endif()

find_library(SOFIA_SIP_UA_LIBRARIES
  NAMES sofia-sip-ua
  HINTS ${_SOFIA_SIP_UA_ROOT_PATHS}
  PATH_SUFFIXES bin lib
)

if(WIN32)
  list(APPEND SOFIA_SIP_UA_LIBRARIES ws2_32 delayimp Winmm Qwave)
endif(WIN32)
list(REMOVE_DUPLICATES SOFIA_SIP_UA_INCLUDE_DIRS)
list(REMOVE_DUPLICATES SOFIA_SIP_UA_LIBRARIES)
set(SOFIA_SIP_UA_CPPFLAGS "")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SOFIASIPUA
  DEFAULT_MSG
  SOFIA_SIP_UA_INCLUDE_DIRS SOFIA_SIP_UA_LIBRARIES
)

mark_as_advanced(SOFIA_SIP_UA_INCLUDE_DIRS SOFIA_SIP_UA_LIBRARIES SOFIA_SIP_UA_CPPFLAGS)
