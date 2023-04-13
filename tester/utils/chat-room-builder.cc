/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "chat-room-builder.hh"

#include <memory>

#include "linphone++/enums.hh"

#include "utils/client-builder.hh"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip {
namespace tester {

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

} // namespace tester
} // namespace flexisip
