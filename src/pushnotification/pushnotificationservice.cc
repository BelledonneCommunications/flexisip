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
#include <sys/types.h>
#include <dirent.h>

#include "pushnotificationservice.hh"
#include "pushnotificationclient.hh"
#include "common.hh"

#include <boost/bind.hpp>
#include <sstream>

const char *APN_DEV_ADDRESS = "gateway.sandbox.push.apple.com";
const char *APN_PROD_ADDRESS = "gateway.push.apple.com";
const char *APN_PORT = "2195";

const char *GPN_ADDRESS = "gcm.googleapis.com";
const char *GPN_PORT = "5235";

const char *WPPN_PORT = "80";

int MAX_QUEUE_SIZE = 10;

using namespace ::std;
namespace ssl = boost::asio::ssl;

int PushNotificationService::sendRequest(const std::shared_ptr<PushNotificationRequest> &pn) {
	std::shared_ptr<PushNotificationClient> client=mClients[pn->getAppIdentifier()];
	if (client==0){
		if (pn->getType().compare(string("wp"))==0) {
			string wpClient = pn->getAppIdentifier();
			std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
			boost::system::error_code err;
			ctx->set_options(ssl::context::default_workarounds, err);
			ctx->set_verify_mode(ssl::context::verify_none);
			mClients[wpClient] = std::make_shared<PushNotificationClient>(wpClient, this, ctx, pn->getAppIdentifier(), WPPN_PORT, MAX_QUEUE_SIZE, false);
			LOGD("Creating PNclient for client %s",pn->getAppIdentifier().c_str());
			client = mClients[wpClient];
		} else {
			LOGE("No push notification certificate for client %s",pn->getAppIdentifier().c_str());
			return -1;
		}
	}
	//this method is called from flexisip main thread, while service is running in its own thread.
	//To avoid using dedicated mutex, use the server post() method to delegate the processing of the push notification to the service thread.
	mIOService.post(std::bind(&PushNotificationClient::sendRequest,client,pn));
	return 0;
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

void PushNotificationService::waitEnd() {
	if (mThread != NULL) {
		LOGD("Waiting for PushNotificationService to end");
		bool finished = false;
		while (!finished) {
			finished = true;
			map<string, std::shared_ptr<PushNotificationClient> >::const_iterator it;
			for (it = mClients.begin(); it != mClients.end(); ++it) {
				if (!it->second->isIdle()) {
					finished = false;
					break;
				}
			}
		}
	}
}

void PushNotificationService::setupClients(const string &certdir, const string &ca, int maxQueueSize) {
	struct dirent *dirent;
	DIR *dirp;
	MAX_QUEUE_SIZE = maxQueueSize;

	// Android Client
	string googleClient = string("google");
	std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
	boost::system::error_code err;
	ctx->set_options(ssl::context::default_workarounds, err);
	ctx->set_verify_mode(ssl::context::verify_none);
	mClients[googleClient]=std::make_shared<PushNotificationClient>(googleClient, this, ctx, GPN_ADDRESS, GPN_PORT, maxQueueSize, true);
	
	dirp=opendir(certdir.c_str());
	if (dirp==NULL){
		LOGE("Could not open push notification certificates directory (%s): %s",certdir.c_str(),strerror(errno));
		return;
	}
	while((dirent=readdir(dirp))!=NULL){
		if (dirent->d_type!=DT_REG && dirent->d_type!=DT_LNK) continue;
		string cert=string(dirent->d_name);
		string certpath= string(certdir)+"/"+cert;
		std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
		boost::system::error_code err;
		ctx->set_options(ssl::context::default_workarounds, err);
		ctx->set_password_callback(bind(&PushNotificationService::handle_password_callback, this, _1, _2));

		if (!ca.empty()) {
			ctx->set_verify_mode(ssl::context::verify_peer);
	#if BOOST_VERSION >= 104800
			ctx->set_verify_callback(bind(&PushNotificationService::handle_verify_callback, this, _1, _2));
	#endif
			ctx->load_verify_file(ca, err);
			if (err) {
				LOGE("load_verify_file: %s",err.message().c_str());
			}
		} else {
			ctx->set_verify_mode(ssl::context::verify_none);
		}
		ctx->add_verify_path("/etc/ssl/certs");

		if (!cert.empty()) {
			ctx->use_certificate_file(certpath, ssl::context::file_format::pem, err);
			if (err) {
				LOGE("use_certificate_file %s: %s",certpath.c_str(), err.message().c_str());
			}
		}
		string key=certpath;
		if (!key.empty()) {
			ctx->use_private_key_file(key, ssl::context::file_format::pem, err);
			if (err) {
				LOGE("use_private_key_file: %s",err.message().c_str());
			}
		}
		string certName = cert.substr(0, cert.size() - 4); // Remove .pem at the end of cert
		const char *apn_server;
		if (certName.find(".dev")!=string::npos)
			apn_server=APN_DEV_ADDRESS;
		else apn_server=APN_PROD_ADDRESS;
		mClients[certName]=std::make_shared<PushNotificationClient>(cert, this, ctx, apn_server, APN_PORT, maxQueueSize, true);
	}
	closedir(dirp);
}

PushNotificationService::PushNotificationService(const std::string &certdir, const std::string &cafile, int maxQueueSize, StatCounter64 *countFailed, StatCounter64 *countSent) :
		mIOService(), mThread(NULL), mCountFailed(countFailed), mCountSent(countSent) {
	setupClients(certdir, cafile, maxQueueSize);
}

PushNotificationService::~PushNotificationService() {
	stop();
}

int PushNotificationService::run() {
	LOGD("PushNotificationService Start");
	boost::asio::io_service::work work(mIOService);
	mIOService.run();
	LOGD("PushNotificationService End");
	return 0;
}

void PushNotificationService::clientEnded() {
}

boost::asio::io_service &PushNotificationService::getService() {
	return mIOService;
}

string PushNotificationService::handle_password_callback(size_t max_length, ssl::context_base::password_purpose purpose) const {
	return mPassword;
}

#if BOOST_VERSION >= 104800
bool PushNotificationService::handle_verify_callback(bool preverified, ssl::verify_context& ctx) const {
	char subject_name[256];
#if not(__GNUC__ == 4 && __GNUC_MINOR__ < 5 )
	SLOGD << "Verifying " << [&] () {
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		return subject_name;
	}();
#else
	X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	SLOGD << "Verifying " << subject_name;
#endif
	return preverified;
}
#endif
