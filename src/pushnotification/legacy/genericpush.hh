/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "flexisip/utils/sip-uri.hh"

#include "legacy-request.hh"

namespace flexisip {
namespace pushnotification {

class GenericRequest : public LegacyRequest {
public:
	// Public ctors
	using LegacyRequest::LegacyRequest;

	// Public methods
	std::tuple<std::string, std::string, std::string> getLegacyParams() const noexcept;
	std::string getAppIdentifier() const noexcept override {
		return "generic";
	}
	const std::string& getFirebaseAuthKey() const noexcept {
		return mFirebaseAuthKey;
	}
	void setFirebaseAuthKey(const std::string& aAuthKey) noexcept {
		mFirebaseAuthKey = aAuthKey;
	}

	const std::vector<char>& getData(const sofiasip::Url& url, Method method) override;

	std::string isValidResponse(const std::string& str) override;
	bool isServerAlwaysResponding() override {
		return true;
	}

private:
	// Private methods
	std::string& substituteArgs(std::string& input);

	// Private attributes
	std::vector<char> mBuffer{};    /**< Buffer returned by getData(). */
	std::string mFirebaseAuthKey{}; /**< Authentication key required by Firebase service. */
};

} // namespace pushnotification
} // namespace flexisip
