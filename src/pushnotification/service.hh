/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

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

#include <condition_variable>
#include <list>
#include <mutex>
#include <string>
#include <thread>

#include <flexisip/configmanager.hh>

#include "client.hh"
#include "request.hh"

namespace flexisip {
namespace pushnotification {

class Service {
public:
	Service(su_root_t &root, unsigned maxQueueSize);
	~Service();

	StatCounter64 *getFailedCounter() const noexcept {return mCountFailed;}
	StatCounter64 *getSentCounter() const noexcept {return mCountSent;}
	void setStatCounters(StatCounter64 *countFailed, StatCounter64 *countSent) {
		mCountFailed = countFailed;
		mCountSent = countSent;
	}

	static std::unique_ptr<Request> makePushRequest(const PushInfo &pinfo);

	int sendPush(const std::shared_ptr<Request> &pn);
	void setupGenericClient(const url_t *url);
	void setupiOSClient(const std::string &certdir, const std::string &cafile);
	void setupFirebaseClient(const std::map<std::string, std::string> &firebaseKeys);
	void setupWindowsPhoneClient(const std::string &packageSID, const std::string &applicationSecret);

	bool isIdle() const noexcept;

private:
	void setupClients(const std::string &certdir, const std::string &ca, int maxQueueSize);
	bool isCertExpired(const std::string &certPath) const noexcept;

	su_root_t &mRoot;
	unsigned mMaxQueueSize{0};
	std::map<std::string, std::unique_ptr<Client>> mClients{};
	std::string mWindowsPhonePackageSID{};
	std::string mWindowsPhoneApplicationSecret{};
	StatCounter64 *mCountFailed{nullptr};
	StatCounter64 *mCountSent{nullptr};
};

}
}
