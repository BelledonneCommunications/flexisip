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

#include "chat-room-builder.hh"

#include <memory>

#include "linphone++/enums.hh"

#include "client-builder.hh"
#include "client-core.hh"
#include "test-patterns/test.hh"

namespace flexisip::tester {

ChatRoomBuilder::ChatRoomBuilder(const CoreClient& client)
    : mClient(client), mParams(mClient.getCore()->createDefaultChatRoomParams()) {
	mParams->setEncryptionBackend(linphone::ChatRoom::EncryptionBackend::None);
}

std::shared_ptr<linphone::ChatRoom>
ChatRoomBuilder::build(const std::initializer_list<std::shared_ptr<const linphone::Address>>& invitees) const {
	if (1 < invitees.size()) {
		BC_HARD_ASSERT_FALSE(mParams->getSubject().empty());
		mParams->enableGroup(true);
	}
	BC_HARD_ASSERT_TRUE(mParams->isValid());

	std::list<std::shared_ptr<linphone::Address>> addresses{};
	for (const auto& address : invitees) {
		addresses.push_back(std::const_pointer_cast<linphone::Address>(address));
	}
	return mClient.getCore()->createChatRoom(mParams, mClient.getMe(), addresses);
}

const ChatRoomBuilder& ChatRoomBuilder::setSubject(const std::string& subject) const {
	mParams->setSubject(subject);
	return *this;
}
const ChatRoomBuilder& ChatRoomBuilder::setBackend(linphone::ChatRoom::Backend backend) const {
	mParams->setBackend(backend);
	return *this;
}
const ChatRoomBuilder& ChatRoomBuilder::setGroup(OnOff toggle) const {
	mParams->enableGroup(bool(toggle));
	return *this;
}

} // namespace flexisip::tester
