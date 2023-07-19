/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

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

#include <condition_variable>
#include <list>
#include <mutex>
#include <string>
#include <thread>

#include "flexisip/configmanager.hh"
#include "flexisip/utils/sip-uri.hh"

#include "client.hh"
#include "pushnotification/generic/generic-enums.hh"
#include "request.hh"

namespace flexisip {
namespace pushnotification {

class Client;
class GenericHttpRequest;

class Service {
public:
	Service(sofiasip::SuRoot& root, unsigned maxQueueSize);
	~Service();

	StatCounter64* getFailedCounter() const noexcept {
		return mCountFailed;
	}
	StatCounter64* getSentCounter() const noexcept {
		return mCountSent;
	}
	void setStatCounters(StatCounter64* countFailed, StatCounter64* countSent) noexcept {
		mCountFailed = countFailed;
		mCountSent = countSent;
	}

	const std::map<std::string, std::shared_ptr<Client>> getClients() {
		return mClients;
	}

	std::shared_ptr<Request> makeRequest(PushType pType, const std::shared_ptr<const PushInfo>& pInfo) const;
	void sendPush(const std::shared_ptr<Request>& pn);
	void setupGenericClient(const sofiasip::Url& url, Method method, Protocol protocol);
	void setupiOSClient(const std::string& certdir, const std::string& cafile);
	void setupFirebaseClients(const std::list<std::string>& firebaseKeys);
	void addFirebaseClient(const std::string& firebaseAppId, const std::string& apiKey = "");

	/**
	 * Add a PN client to use when no other client can handle a PN request
	 * given to sendPush().
	 */
	void setFallbackClient(const std::shared_ptr<Client>& fallbackClient);

	bool isIdle() const noexcept;

	static const std::string sGenericClientName;

private:
	// Private attributes
	sofiasip::SuRoot& mRoot;
	unsigned mMaxQueueSize{0};
	std::map<std::string, std::shared_ptr<Client>> mClients{};
	std::string mWindowsPhonePackageSID{};
	std::string mWindowsPhoneApplicationSecret{};
	StatCounter64* mCountFailed{nullptr};
	StatCounter64* mCountSent{nullptr};

	static const std::string sFallbackClientKey;
};

} // namespace pushnotification
} // namespace flexisip
