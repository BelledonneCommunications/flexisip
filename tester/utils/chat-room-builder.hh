/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <initializer_list>
#include <memory>

#include "linphone++/chat_room.hh"
#include "linphone++/enums.hh"

#include "client-builder.hh"

namespace flexisip::tester {

class CoreClient;

class ChatRoomBuilder {
public:
	explicit ChatRoomBuilder(const CoreClient&);

	const ChatRoomBuilder& setSubject(const std::string&) const;
	const ChatRoomBuilder& setBackend(linphone::ChatRoom::Backend) const;
	const ChatRoomBuilder& setGroup(OnOff) const;
	std::shared_ptr<linphone::ChatRoom>
	build(const std::initializer_list<std::shared_ptr<const linphone::Address>>&) const;

private:
	const CoreClient& mClient;
	const std::shared_ptr<linphone::ChatRoomParams> mParams;
};

} // namespace flexisip::tester
