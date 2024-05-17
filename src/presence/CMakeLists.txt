############################################################################
# CMakeLists.txt
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

target_sources(flexisip PRIVATE
        belle-sip-using.hh
        bellesip-signaling-exception.cc bellesip-signaling-exception.hh
        observers/presence-auth-db-listener.cc observers/presence-auth-db-listener.hh
        observers/presence-info-observer.hh
        observers/presence-longterm.cc observers/presence-longterm.hh
        presence-server.cc presence-server.hh
        presentity/presentity-manager.cc presentity/presentity-manager.hh
        presentity/presence-information-element.cc presentity/presence-information-element.hh
        presentity/presence-information-element-map.cc presentity/presence-information-element-map.hh
        presentity/presentity-manager-interface.hh
        presentity/presentity-presence-information.cc presentity/presentity-presence-information.hh
        presentity/presentity-presence-information-listener.cc presentity/presentity-presence-information-listener.hh
        subscription/body-list-subscription.cc subscription/body-list-subscription.hh
        subscription/list-subscription.cc subscription/list-subscription.hh
        subscription/subscription.cc subscription/subscription.hh
)

if (ENABLE_SOCI)
    target_sources(flexisip PRIVATE
            subscription/external-list-subscription.cc
            subscription/external-list-subscription.hh
    )
endif ()
