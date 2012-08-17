/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#include "pushnotificationservice.h"
#include "pushnotificationclient.h"
#include "common.hh"

#include <boost/bind.hpp>
#include <sstream>

const char *APN_ADDRESS = "gateway.sandbox.push.apple.com";
const char *APN_PORT = "2195";

using namespace ::std;
using namespace ::boost;

void PushNotificationService::sendRequest(const std::shared_ptr<PushNotificationRequest> &pn) {
	while (1) {
		for (list<PushNotificationClient*>::iterator it = mClients.begin(); it != mClients.end(); ++it) {
			if ((*it)->isReady()) {
				(*it)->setData(pn->getData());
				(*it)->start(APN_ADDRESS, APN_PORT);
				return;
			}
		}
		// Wait for free thread
		LOGD("No ready Client... Waiting");
		unique_lock<mutex> lock(mMutex);
		mClientCondition.wait(lock);
	}
}

void PushNotificationService::start() {
	if (mThread == NULL || !mThread->joinable()) {
		delete mThread;
		mThread = NULL;
	}
	if (mThread == NULL) {
		LOGD("Start PushNotificationService");
		mHaveToStop = false;
		mThread = new thread(&PushNotificationService::run, this);
	}
}

void PushNotificationService::stop() {
	if (mThread != NULL) {
		LOGD("Stopping PushNotificationService");
		mHaveToStop = true;
		mIOService.stop();
		if (mThread->joinable()) {
			mThread->join();
		}
		delete mThread;
		mThread = NULL;
	}
}

PushNotificationService::PushNotificationService(int max_client, const string &ca, const string &cert, const string &key, const string &password) :
		mIOService(), mContext(mIOService, asio::ssl::context::sslv23_client), mThread(NULL), mPassword(password) {
	system::error_code err;
	mContext.set_options(asio::ssl::context::default_workarounds, err);
	mContext.set_password_callback(bind(&PushNotificationService::handle_password_callback, this, _1, _2));

	if (!ca.empty()) {
		mContext.set_verify_mode(asio::ssl::context::verify_peer);
#if BOOST_VERSION >= 104800
		mContext.set_verify_callback(bind(&PushNotificationService::handle_verify_callback, this, _1, _2));
#endif
		mContext.load_verify_file(ca, err);
		if (err) {
			cerr << err << endl;
		}
	} else {
		mContext.set_verify_mode(asio::ssl::context::verify_none);
	}

	if (!cert.empty()) {
		mContext.use_certificate_file(cert, asio::ssl::context::file_format::pem, err);
		if (err) {
			cerr << err << endl;
		}
	}

	if (!key.empty()) {
		mContext.use_private_key_file(key, asio::ssl::context::file_format::pem, err);
		if (err) {
			cerr << err << endl;
		}
	}

	// Create clients
	for (int i = 0; i < max_client; ++i) {
		stringstream ss;
		ss << "Client " << i;
		mClients.push_back(new PushNotificationClient(ss.str(), this));
	}
}

PushNotificationService::~PushNotificationService() {
	stop();

	// Delete clients
	while (!mClients.empty()) {
		PushNotificationClient *client = mClients.front();
		mClients.pop_front();
		delete client;
	}
}

int PushNotificationService::run() {
	LOGD("PushNotificationService Start");
	asio::io_service::work work(mIOService);
	mIOService.run();
	LOGD("PushNotificationService End");
	return 0;
}

void PushNotificationService::clientEnded() {
	unique_lock<mutex> lock(mMutex);
	mClientCondition.notify_all();
}

asio::io_service &PushNotificationService::getService() {
	return mIOService;
}

asio::ssl::context &PushNotificationService::getContext() {
	return mContext;
}

string PushNotificationService::handle_password_callback(size_t max_length, asio::ssl::context_base::password_purpose purpose) const {
	return mPassword;
}

#if BOOST_VERSION >= 104800
bool PushNotificationService::handle_verify_callback(bool preverified, asio::ssl::verify_context& ctx) const {
	if (IS_LOGD) {
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		LOGD("Verifying %s", subject_name);
	}
	return preverified;
}
#endif
