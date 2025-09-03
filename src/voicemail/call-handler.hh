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

#pragma once

#include <filesystem>

#include "linphone++/linphone.hh"

#include "flexisip/logmanager.hh"

class CallHandler : public std::enable_shared_from_this<CallHandler>,
                    public linphone::PlayerListener,
                    public linphone::CallListener {
public:
	explicit CallHandler(std::shared_ptr<linphone::Call> call) : mCall(call) {
		mLogPrefix = flexisip::LogManager::makeLogPrefixForInstance(this, "CallHandler");
	}
	~CallHandler() override = default;

	void terminateCall();
	void playAnnounce(const std::filesystem::path& announcePath);

protected:
	// Player listener
	void onEofReached(const std::shared_ptr<linphone::Player>& player) override;

	// Call listener
	void onStateChanged(const std::shared_ptr<linphone::Call>& call,
	                    linphone::Call::State state,
	                    const std::string& message) override;

private:
	void terminateCall(const std::shared_ptr<linphone::Player>& player);

	std::string mLogPrefix;
	const std::shared_ptr<linphone::Call> mCall;
};
