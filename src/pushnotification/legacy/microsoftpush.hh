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

#include "pushnotification/legacy/legacy-request.hh"

namespace flexisip {
namespace pushnotification {

class MicrosoftRequest : public LegacyRequest {
public:
	using LegacyRequest::LegacyRequest;

	virtual void createHTTPRequest(const std::string& access_token) = 0;

	const std::vector<char>& getData(const sofiasip::Url& url, Method method) override;
	std::string isValidResponse(const std::string& str) override;
	bool isServerAlwaysResponding() override {
		return true;
	}

protected:
	virtual void checkResponseLine(const std::string& line, bool& isValid, bool& isConnect, bool& isNotif) const = 0;

	void createPushNotification();

	std::vector<char> mBuffer{};
	std::string mHttpHeader{};
	std::string mHttpBody{};
};

class WindowsPhoneRequest : public MicrosoftRequest {
public:
	template <typename T>
	WindowsPhoneRequest(PushType pType, T&& pinfo) : MicrosoftRequest{pType, std::forward<T>(pinfo)} {
		createHTTPRequest("");
	}

	void createHTTPRequest(const std::string& access_token) override;

private:
	void checkResponseLine(const std::string& line, bool& isValid, bool& isConnect, bool& isNotif) const override;
};

class Windows10Request : public MicrosoftRequest {
public:
	using MicrosoftRequest::MicrosoftRequest;

	void createHTTPRequest(const std::string& access_token) override;

private:
	void checkResponseLine(const std::string& line, bool& isValid, bool& isConnect, bool& isNotif) const override;
};

} // namespace pushnotification
} // namespace flexisip
