############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2026 Belledonne Communications, Grenoble France
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
	config.cc config.hh
	flexi-stats.cc flexi-stats.hh
	flexiapi.cc flexiapi.hh
	schemas/account/account.hh
	schemas/account/account-json.cc schemas/account/account-json.hh
	schemas/account/call-forwarding.hh
	schemas/account/group.hh
	schemas/account/resolved-uri.cc schemas/account/resolved-uri.hh
	schemas/account/uri-type.hh
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
	schemas/pushnotification/pushnotification.hh
	schemas/schemas-json.cc schemas/schemas-json.hh
	schemas/space/realm.hh
	schemas/space/realm-json.cc schemas/space/realm-json.hh
	schemas/space/space.hh
	schemas/space/space-json.cc schemas/space/space-json.hh
	schemas/voicemail/slot.hh
	schemas/voicemail/slot-creation.hh
)
