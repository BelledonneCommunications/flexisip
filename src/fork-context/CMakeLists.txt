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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# ###########################################################################

target_sources(flexisip PRIVATE
    branch-info.hh branch-info.cc
    fork-context.cc fork-context.hh
    fork-context-impl.cc fork-context-impl.hh
    fork-context-factory.cc fork-context-factory.hh
    fork-message-context.cc fork-message-context.hh
    fork-status.hh
    message-kind.cc message-kind.hh
    fork-message-db/branch-info-db.hh
    fork-message-db/fork-message-context-db.hh
    fork-strategy/basic-fork-strategy.cc fork-strategy/basic-fork-strategy.hh
    fork-strategy/call-fork-strategy.cc fork-strategy/call-fork-strategy.hh
    fork-strategy/message-fork-strategy.cc fork-strategy/message-fork-strategy.hh
    fork-strategy/urgent-codes.hh
)

if(ENABLE_SOCI)
    target_sources(flexisip PRIVATE
        fork-message-db/fork-message-context-soci-repository.cc fork-message-db/fork-message-context-soci-repository.hh
        fork-message-db/fork-message-context-db-proxy.cc fork-message-db/fork-message-context-db-proxy.hh
    )
endif()
