/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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
#include "pushnotification.hh"
#include <flexisip/configmanager.hh>

#include <list>

#include <condition_variable>
#include <mutex>
#include <thread>
#include <string>

class PushNotificationClient;

class PushNotificationService {
	friend class PushNotificationClient;

  public:
	PushNotificationService(int maxQueueSize);
	~PushNotificationService();

	void setStatCounters(StatCounter64 *countFailed, StatCounter64 *countSent) {
		mCountFailed = countFailed;
		mCountSent = countSent;
	}

	int sendPush(const std::shared_ptr<PushNotificationRequest> &pn);
	void setupGenericClient(const url_t *url);
	void setupiOSClient(const std::string &certdir, const std::string &cafile);
	void setupAndroidClient(const std::map<std::string, std::string> googleKeys);
	void setupFirebaseClient(const std::map<std::string, std::string> firebaseKeys);
	void setupWindowsPhoneClient(const std::string& packageSID, const std::string& applicationSecret);

	bool isIdle();
  private:
	void setupClients(const std::string &certdir, const std::string &ca, int maxQueueSize);
	bool isCertExpired( const std::string &certPath );


  private:
	std::thread *mThread;
	int mMaxQueueSize;
	bool mHaveToStop;
	std::map<std::string, std::shared_ptr<PushNotificationClient>> mClients;
	std::string mPassword;
	std::string mWindowsPhonePackageSID, mWindowsPhoneApplicationSecret;
	StatCounter64 *mCountFailed;
	StatCounter64 *mCountSent;
};
