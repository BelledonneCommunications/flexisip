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
        flexi-stats.cc flexi-stats.hh
        schemas/api-formatted-uri.hh
        schemas/call/call.hh
        schemas/call/call-device-state.hh
        schemas/call/terminated.hh
        schemas/conference/conference.hh
        schemas/conference/participant-device-event.hh
        schemas/conference/participant-event.hh
        schemas/iso-8601-date.hh
        schemas/message/message.hh
        schemas/message/message-device-response.hh
        schemas/optional-json.hh
        )
