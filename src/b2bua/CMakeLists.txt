############################################################################
# CMakeLists.txt
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
############################################################################

# TODO Change back to lowercase `jsoncpp` when (if) the SDK decides to use it as well
# https://linphone.atlassian.net/browse/SDK-184
find_package(JsonCPP "1.1.0" REQUIRED)

target_sources(flexisip PRIVATE
        async-stop-core.cc async-stop-core.hh
        b2bua-server.cc b2bua-server.hh
        sip-bridge/accounts/account-pool.cc sip-bridge/accounts/account-pool.hh
        sip-bridge/accounts/account.cc sip-bridge/accounts/account.hh
        sip-bridge/accounts/loaders/loader.hh
        sip-bridge/accounts/loaders/sql-account-loader.cc sip-bridge/accounts/loaders/sql-account-loader.hh
        sip-bridge/accounts/loaders/static-account-loader.hh
        sip-bridge/accounts/redis-account-pub.hh
        sip-bridge/accounts/selection-strategy/find-in-pool.cc sip-bridge/accounts/selection-strategy/find-in-pool.hh
        sip-bridge/configuration/media-encryption.hh
        sip-bridge/configuration/v1.hh
        sip-bridge/configuration/v2/account.hh
        sip-bridge/configuration/v2/v2.cc sip-bridge/configuration/v2/v2.hh
        sip-bridge/sip-bridge.cc sip-bridge/sip-bridge.hh
        sip-bridge/sip-provider.cc sip-bridge/sip-provider.hh
        sip-bridge/invite-tweaker.cc sip-bridge/invite-tweaker.hh
        sip-bridge/trigger-strategy.cc sip-bridge/trigger-strategy.hh
        trenscrypter.cc trenscrypter.hh
)

target_link_libraries(flexisip
        PUBLIC liblinphone++ liblinphone
)
target_link_libraries(flexisip PRIVATE
        jsoncpp_lib
        mediastreamer2
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND (HAS_GCC_BUG_105616 OR HAS_GCC_BUG_105562))
    set_source_files_properties(
            b2bua/sip-bridge/sip-bridge.cc
            b2bua/trenscrypter.cc
            PROPERTIES COMPILE_OPTIONS "-Wno-error=maybe-uninitialized")
endif ()