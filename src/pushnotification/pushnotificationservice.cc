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
#include <sys/types.h>
#include <dirent.h>

#include "pushnotificationservice.hh"
#include "pushnotificationclient.hh"
#include "common.hh"

#include <boost/bind.hpp>
#include <sstream>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>


static const char *APN_DEV_ADDRESS = "gateway.sandbox.push.apple.com";
static const char *APN_PROD_ADDRESS = "gateway.push.apple.com";
static const char *APN_PORT = "2195";

static const char *GPN_ADDRESS = "android.googleapis.com";
static const char *GPN_PORT = "443";

static const char *WPPN_PORT = "80";

using namespace ::std;
namespace ssl = boost::asio::ssl;

int PushNotificationService::sendRequest(const std::shared_ptr<PushNotificationRequest> &pn) {
	std::shared_ptr<PushNotificationClient> client = mClients[pn->getAppIdentifier()];
	if (client == 0) {
		if (pn->getType().compare(string("wp")) == 0) {
			string wpClient = pn->getAppIdentifier();
			std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
			boost::system::error_code err;
			ctx->set_options(ssl::context::default_workarounds, err);
			ctx->set_verify_mode(ssl::context::verify_none);
			mClients[wpClient] = std::make_shared<PushNotificationClient>(wpClient, this, ctx, pn->getAppIdentifier(),
																		  WPPN_PORT, mMaxQueueSize, false);
			LOGD("Creating PN client for %s", pn->getAppIdentifier().c_str());
			client = mClients[wpClient];
		} else {
			LOGE("No push notification certificate for client %s", pn->getAppIdentifier().c_str());
			return -1;
		}
	}
	// this method is called from flexisip main thread, while service is running in its own thread.
	// To avoid using dedicated mutex, use the server post() method to delegate the processing of the push notification
	// to the service thread.
	mIOService.post(std::bind(&PushNotificationClient::sendRequest, client, pn));
	return 0;
}

void PushNotificationService::start() {
	if (mThread && !mThread->joinable()) {
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
			map<string, std::shared_ptr<PushNotificationClient>>::const_iterator it;
			for (it = mClients.begin(); it != mClients.end(); ++it) {
				if (!it->second->isIdle()) {
					finished = false;
					break;
				}
			}
		}
		usleep(100000); // avoid eating all cpu for nothing
	}
}

void PushNotificationService::setupErrorClient() {
	// Error client
	std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
	boost::system::error_code err;
	ctx->set_options(ssl::context::default_workarounds, err);
	ctx->set_verify_mode(ssl::context::verify_none);
	mClients["error"] =
		std::make_shared<PushNotificationClient>("error", this, ctx, "127.0.0.1", "1", mMaxQueueSize, false);
}

void PushNotificationService::setupGenericClient(const url_t *url) {
	std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
	boost::system::error_code err;
	ctx->set_options(ssl::context::default_workarounds, err);
	ctx->set_verify_mode(ssl::context::verify_none);
	mClients["generic"] = std::make_shared<PushNotificationClient>("generic", this, ctx, url->url_host, url_port(url),
																   mMaxQueueSize, false);
}

/* Utility function to convert ASN1_TIME to a printable string in a buffer */
static int ASN1_TIME_toString( const ASN1_TIME* time, char* buffer, uint32_t buff_length){
	int write = 0;
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio) {
		if (ASN1_TIME_print(bio, time))
			write = BIO_read(bio, buffer, buff_length-1);
		BIO_free(bio);
	}
	buffer[write]='\0';
	return write;
}

bool PushNotificationService::isCertExpired( const std::string &certPath ){
	bool expired = true;
	BIO* certbio = BIO_new(BIO_s_file());
	int err = BIO_read_filename(certbio, certPath.c_str());
	if( err == 0 ){
		LOGE("BIO_read_filename failed for %s", certPath.c_str());
		return expired;
	}
	
	X509* cert = PEM_read_bio_X509(certbio, NULL, 0, 0);
	if( !cert ){
		char buf[128] = {};
		unsigned long error = ERR_get_error();
		ERR_error_string(error, buf);
		LOGE("Couldn't parse certificate at %s : %s", certPath.c_str(), buf);
		return expired;
	} else {
		ASN1_TIME *notBefore = X509_get_notBefore(cert);
		ASN1_TIME *notAfter = X509_get_notAfter(cert);
		if( X509_cmp_current_time(notBefore) > 0 && X509_cmp_current_time(notAfter) < 0 ) {

			LOGD("Certificate %s has a valid expiration.", certPath.c_str());
			expired = false;
		} else {
			// the certificate has an expire or not before value that makes it not valid regarding the server's date.
			char beforeStr[128] = {};
			char afterStr[128] = {};
			if( ASN1_TIME_toString(notBefore, beforeStr, 128) && ASN1_TIME_toString(notAfter, afterStr, 128)){
				LOGD("Certificate %s is expired or not yet valid! Not Before: %s, Not After: %s", certPath.c_str(),
					 beforeStr, afterStr);
			} else {
				LOGD("Certificate %s is expired or not yet valid!", certPath.c_str());
			}
		}
	}
	X509_free(cert);
	BIO_free_all(certbio);
	
	return expired;
}

void PushNotificationService::setupiOSClient(const std::string &certdir, const std::string &cafile) {
	struct dirent *dirent;
	DIR *dirp;

	dirp = opendir(certdir.c_str());
	if (dirp == NULL) {
		LOGE("Could not open push notification certificates directory (%s): %s", certdir.c_str(), strerror(errno));
		return;
	}
	SLOGD << "Searching push notification client on dir [" << certdir << "]";

	while (true) {
		errno = 0;
		if ((dirent = readdir(dirp)) == NULL) {
			if (errno)
				SLOGE << "Cannot read dir [" << certdir << "] because [" << strerror(errno) << "]";
			break;
		}

		string cert = string(dirent->d_name);
		// only consider files which end with .pem
		string suffix = ".pem";
		if (cert.compare(".") == 0 || cert.compare("..") == 0 ||
			(cert.compare(cert.length() - suffix.length(), suffix.length(), suffix) != 0)) {
			continue;
		}
		string certpath = string(certdir) + "/" + cert;
		std::shared_ptr<ssl::context> context(new ssl::context(mIOService, ssl::context::sslv23_client));
		boost::system::error_code error;
		context->set_options(ssl::context::default_workarounds, error);
		context->set_password_callback(bind(&PushNotificationService::handle_password_callback, this, _1, _2));

		if (!cafile.empty()) {
			context->set_verify_mode(ssl::context::verify_peer);
#if BOOST_VERSION >= 104800
			context->set_verify_callback(bind(&PushNotificationService::handle_verify_callback, this, _1, _2));
#endif
			context->load_verify_file(cafile, error);
			if (error) {
				LOGE("load_verify_file: %s", error.message().c_str());
				continue;
			}
		} else {
			context->set_verify_mode(ssl::context::verify_none);
		}
		context->add_verify_path("/etc/ssl/certs");

		if (!cert.empty()) {
			context->use_certificate_file(certpath, ssl::context::file_format::pem, error);
			if (error) {
				LOGE("use_certificate_file %s: %s", certpath.c_str(), error.message().c_str());
				continue;
			} else if ( isCertExpired(certpath) ){
				LOGF("Certificate %s is expired! You won't be able to use it for push notifications. Please update your certificate or remove it entirely.", certpath.c_str());
				// will exit flexisip
			}
		}
		string key = certpath;
		if (!key.empty()) {
			context->use_private_key_file(key, ssl::context::file_format::pem, error);
			if (error) {
				LOGE("use_private_key_file %s: %s", certpath.c_str(), error.message().c_str());
				continue;
			}
		}
		string certName = cert.substr(0, cert.size() - 4); // Remove .pem at the end of cert
		const char *apn_server;
		if (certName.find(".dev") != string::npos)
			apn_server = APN_DEV_ADDRESS;
		else
			apn_server = APN_PROD_ADDRESS;
		mClients[certName] =
			std::make_shared<PushNotificationClient>(cert, this, context, apn_server, APN_PORT, mMaxQueueSize, true);
		SLOGD << "Adding ios push notification client [" << certName << "]";
	}
	closedir(dirp);
}

void PushNotificationService::setupAndroidClient(const std::map<std::string, std::string> googleKeys) {
	map<string, string>::const_iterator it;
	for (it = googleKeys.begin(); it != googleKeys.end(); ++it) {
		string android_app_id = it->first;

		std::shared_ptr<ssl::context> ctx(new ssl::context(mIOService, ssl::context::sslv23_client));
		boost::system::error_code err;
		ctx->set_options(ssl::context::default_workarounds, err);
		ctx->set_verify_mode(ssl::context::verify_none);

		mClients[android_app_id] =
			std::make_shared<PushNotificationClient>("google", this, ctx, GPN_ADDRESS, GPN_PORT, mMaxQueueSize, true);
		SLOGD << "Adding android push notification client [" << android_app_id << "]";
	}
}

PushNotificationService::PushNotificationService(int maxQueueSize)
	: mIOService(), mThread(NULL), mMaxQueueSize(maxQueueSize), mClients(), mCountFailed(NULL), mCountSent(NULL) {
	setupErrorClient();
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

string PushNotificationService::handle_password_callback(size_t max_length,
														 ssl::context_base::password_purpose purpose) const {
	return mPassword;
}

bool PushNotificationService::handle_verify_callback(bool preverified, ssl::verify_context &ctx) const {
	char subject_name[256];
	
	X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	SLOGD << "Verifying " << subject_name;
	
	int error = X509_STORE_CTX_get_error(ctx.native_handle());
	if( error != 0 ){
		switch (error) {
			case X509_V_ERR_CERT_NOT_YET_VALID:
			case X509_V_ERR_CRL_NOT_YET_VALID:
				LOGE("Certificate for %s is not yet valid. Push won't work.", subject_name);
				break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CRL_HAS_EXPIRED:
				LOGE("Certificate for %s is expired. Push won't work.", subject_name);
				break;
				
			default:{
				const char* errString = X509_verify_cert_error_string(error);
				LOGE("Certificate for %s is invalid (reason: %d - %s). Push won't work.", subject_name, error, errString ? errString:"unknown" );
				break;
			}
		}
	}
	
	return preverified;
}
