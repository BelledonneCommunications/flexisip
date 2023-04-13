/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <initializer_list>
#include <memory>

#include "linphone++/enums.hh"
#include <linphone++/chat_room.hh>

#include "utils/client-builder.hh"

namespace flexisip {
namespace tester {

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

} // namespace tester
} // namespace flexisip
