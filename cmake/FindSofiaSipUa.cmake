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
#  SOFIASIPUA_FOUND - system has sofia-sip
#  SOFIASIPUA_INCLUDE_DIRS - the sofia-sip include directory
#  SOFIASIPUA_LIBRARIES - The libraries needed to use sofia-sip
#  SOFIASIPUA_CPPFLAGS - The cflags needed to use sofia-sip


set(_SOFIASIPUA_ROOT_PATHS
  ${WITH_SOFIASIPUA}
  ${CMAKE_INSTALL_PREFIX}
)

find_path(SOFIASIPUA_INCLUDE_DIRS
  NAMES sofia-sip/sip.h
  HINTS _SOFIASIPUA_ROOT_PATHS
  PATH_SUFFIXES include/sofia-sip-1.13 include/sofia-sip-1.12
)

if(SOFIASIPUA_INCLUDE_DIRS)
  set(HAVE_SOFIASIPUA_SOFIASIPUA_H 1)
endif()

find_library(SOFIASIPUA_LIBRARIES
  NAMES sofia-sip-ua
  HINTS ${_SOFIASIPUA_ROOT_PATHS}
  PATH_SUFFIXES bin lib
)

if(WIN32)
  list(APPEND SOFIASIPUA_LIBRARIES ws2_32 delayimp Winmm Qwave)
endif(WIN32)
list(REMOVE_DUPLICATES SOFIASIPUA_INCLUDE_DIRS)
list(REMOVE_DUPLICATES SOFIASIPUA_LIBRARIES)
set(SOFIASIPUA_CPPFLAGS "")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SofiaSipUa
  DEFAULT_MSG
  SOFIASIPUA_INCLUDE_DIRS SOFIASIPUA_LIBRARIES
)

mark_as_advanced(SOFIASIPUA_INCLUDE_DIRS SOFIASIPUA_LIBRARIES SOFIASIPUA_CPPFLAGS)
