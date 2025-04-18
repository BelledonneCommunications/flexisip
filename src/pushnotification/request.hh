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

#include <memory>
#include <sstream>
#include <string>

#include "push-info.hh"
#include "push-type.hh"
#include "rfc8599-push-params.hh"

namespace flexisip {
namespace pushnotification {

class Request {
public:
	enum class State { NotSubmitted, InProgress, Successful, Failed };

	Request(PushType pType, const std::shared_ptr<const PushInfo>& pInfo);
	Request(const Request&) = delete;
	virtual ~Request() = default;

	PushType getPushType() const noexcept {
		return mPType;
	}
	const PushInfo& getPInfo() const noexcept {
		return *mPInfo;
	}
	const RFC8599PushParams& getDestination() const noexcept {
		return *mPInfo->mDestinations.at(mPType);
	}

	State getState() const noexcept {
		return mState;
	}
	void setState(State state) noexcept;
	virtual std::string getAppIdentifier() const noexcept {
		return getDestination().getAppIdentifier();
	}

protected:
	// Protected methods
	std::string quoteStringIfNeeded(const std::string& str) const noexcept;
	std::string getPushTimeStamp() const noexcept;

	// Protected attributes
	PushType mPType{PushType::Unknown};
	std::shared_ptr<const PushInfo> mPInfo{};
	State mState{State::NotSubmitted};

private:
	std::string mLogPrefix;
};

std::ostream& operator<<(std::ostream& os, Request::State state) noexcept;

} // namespace pushnotification
} // namespace flexisip