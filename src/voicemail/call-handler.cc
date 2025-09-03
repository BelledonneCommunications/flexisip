/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "call-handler.hh"

#include <filesystem>

void CallHandler::terminateCall() {
	const auto player = mCall->getPlayer();
	terminateCall(player);
}

void CallHandler::terminateCall(const std::shared_ptr<linphone::Player>& player) {
	LOGD << "Terminating call";
	player->close();
	player->removeListener(shared_from_this());
	mCall->terminate();
}

void CallHandler::playAnnounce(const std::filesystem::path& announcePath) {
	mCall->addListener(shared_from_this());
	const auto player = mCall->getPlayer();
	player->addListener(shared_from_this());
	player->open(announcePath);
	player->start();
}

void CallHandler::onEofReached(const std::shared_ptr<linphone::Player>& player) {
	LOGD << "Terminating call";
	terminateCall(player);
}

void CallHandler::onStateChanged(const std::shared_ptr<linphone::Call>& call,
                                 linphone::Call::State state,
                                 const std::string&) {
	if (state != linphone::Call::State::End) return;
	call->getPlayer()->removeListener(shared_from_this());
	call->removeListener(shared_from_this());
}