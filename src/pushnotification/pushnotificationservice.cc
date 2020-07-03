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

#include <sstream>

#include <sys/types.h>

#include <dirent.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <flexisip/common.hh>

#include <utils/make-unique.hh>

#include "pushnotificationclient.hh"
#include "pushnotificationclient_wp.hh"
#include "pushnotificationservice.hh"

using namespace std;

namespace flexisip {

static constexpr const char *APN_DEV_ADDRESS = "gateway.sandbox.push.apple.com";
static constexpr const char *APN_PROD_ADDRESS = "gateway.push.apple.com";
static constexpr const char *APN_PORT = "2195";

static constexpr const char *FIREBASE_ADDRESS = "fcm.googleapis.com";
static constexpr const char *FIREBASE_PORT = "443";

static constexpr const char *WPPN_PORT = "443";

PushNotificationService::PushNotificationService(unsigned maxQueueSize) : mMaxQueueSize(maxQueueSize) {
	SSL_library_init();
	SSL_load_error_strings();
}

PushNotificationService::~PushNotificationService() {
	ERR_free_strings();
}


int PushNotificationService::sendPush(const std::shared_ptr<PushNotificationRequest> &pn){	
	auto client = mClients[pn->getAppIdentifier()].get();
	if (client == nullptr) {
		auto isW10 = (pn->getType() == "w10");
		auto isWP = (pn->getType() == "wp");
		if(isW10 || isWP) {
			// In Windows case we can't create all push notification clients at start up since we need to wait the registration of all AppID
			// Therefore we create the push notification client just before sending the push.
			if (isW10 && (mWindowsPhonePackageSID.empty() || mWindowsPhoneApplicationSecret.empty())) {
				SLOGE << "Windows Phone not configured for push notifications ("
					"package sid is " << (mWindowsPhonePackageSID.empty() ? "NOT configured" : "configured") << " and " <<
					"application secret is " << (mWindowsPhoneApplicationSecret.empty() ? "NOT configured" : "configured") << ").";
				return -1;
			} else {
				auto wpClient = pn->getAppIdentifier();
			
				using SSLCtxUniquePtr = PushNotificationTransportTls::SSLCtxUniquePtr;
				SSLCtxUniquePtr ctx{SSL_CTX_new(TLSv1_2_method())};
				SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);
			
				LOGD("Creating PN client for %s", pn->getAppIdentifier().c_str());
				if(isW10) {
					mClients[wpClient] = make_unique<PushNotificationClientWp>(
						make_unique<PushNotificationTransportTls>(move(ctx), pn->getAppIdentifier(), WPPN_PORT, true),
						wpClient,
						*this,
						mMaxQueueSize,
						mWindowsPhonePackageSID,
						mWindowsPhoneApplicationSecret
					);
				} else {
					mClients[wpClient] = make_unique<PushNotificationClient>(
						make_unique<PushNotificationTransportTls>(move(ctx), pn->getAppIdentifier(), "80", false),
						wpClient,
						*this,
						mMaxQueueSize
					);
				}
				client = mClients[wpClient].get();
			}
		} else {
			SLOGE << "No push notification client available for push notification request : " << pn;
			return -1;
		}
	}
	client->sendPush(pn);
	return 0;
}

bool PushNotificationService::isIdle() const noexcept {
	for (const auto &entry : mClients) {
		if (!entry.second->isIdle()) return false;
	}
	return true;
}


void PushNotificationService::setupGenericClient(const url_t *url) {
	PushNotificationTransportTls::SSLCtxUniquePtr ctx{SSL_CTX_new(TLSv1_client_method())};
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);

	mClients["generic"] = make_unique<PushNotificationClient>(
		make_unique<PushNotificationTransportTls>(move(ctx), url->url_host, url_port(url), url->url_type == url_https),
		"generic",
		*this,
		mMaxQueueSize
	);
}

/* Utility function to convert ASN1_TIME to a printable string in a buffer */
static int ASN1_TIME_toString( const ASN1_TIME* time, char* buffer, uint32_t buff_length){
	int write = 0;
	BIO* bio = BIO_new(BIO_s_mem());
	if (bio) {
		if (ASN1_TIME_print(bio, time))
			write = BIO_read(bio, buffer, buff_length-1);
		BIO_free_all(bio);
	}
	buffer[write]='\0';
	return write;
}

bool PushNotificationService::isCertExpired( const std::string &certPath) const noexcept {
	bool expired = true;
	BIO* certbio = BIO_new(BIO_s_file());
	int err = BIO_read_filename(certbio, certPath.c_str());
	if( err == 0 ){
		LOGE("BIO_read_filename failed for %s", certPath.c_str());
		BIO_free_all(certbio);
		return expired;
	}

	X509* cert = PEM_read_bio_X509(certbio, NULL, 0, 0);
	if( !cert ){
		char buf[128] = {};
		unsigned long error = ERR_get_error();
		ERR_error_string(error, buf);
		LOGE("Couldn't parse certificate at %s : %s", certPath.c_str(), buf);
		BIO_free_all(certbio);
		return expired;
	} else {
		ASN1_TIME *notBefore = X509_get_notBefore(cert);
		ASN1_TIME *notAfter = X509_get_notAfter(cert);
		char beforeStr[128] = {};
		char afterStr[128] = {};
		int validDates = ( ASN1_TIME_toString(notBefore, beforeStr, 128) && ASN1_TIME_toString(notAfter, afterStr, 128));
		if( X509_cmp_current_time(notBefore) <= 0 && X509_cmp_current_time(notAfter) >= 0 ) {
			LOGD("Certificate %s has a valid expiration: %s.", certPath.c_str(), afterStr);
			expired = false;
		} else {
			// the certificate has an expire or not before value that makes it not valid regarding the server's date.
			if (validDates) {
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

int handle_verify_callback(X509_STORE_CTX* mCtx, void* ud) {
	char subject_name[256];

	X509 *cert = X509_STORE_CTX_get_current_cert(mCtx);
	if (!cert) {
		SLOGE << "No certificate found!";
		return 0;
	}
	X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
	SLOGD << "Verifying " << subject_name;

	int error = X509_STORE_CTX_get_error(mCtx);
	if( error != 0 ){
		switch (error) {
			case X509_V_ERR_CERT_NOT_YET_VALID:
			case X509_V_ERR_CRL_NOT_YET_VALID:
			SLOGE << "Certificate for " <<  subject_name << " is not yet valid. Push won't work.";
			break;
			case X509_V_ERR_CERT_HAS_EXPIRED:
			case X509_V_ERR_CRL_HAS_EXPIRED:
			SLOGE << "Certificate for " <<  subject_name << " is expired. Push won't work.";
			break;
			default:{
				const char* errString = X509_verify_cert_error_string(error);
				SLOGE << "Certificate for " << subject_name << " is invalid (reason: " << error << ": " << (errString ? errString:"unknown") << "). Push won't work.";
				break;
			}
		}
	}

	return 0;
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
		if (cert.compare(".") == 0 || cert.compare("..") == 0 || cert.length() <= suffix.length() ||
			(cert.compare(cert.length() - suffix.length(), suffix.length(), suffix) != 0)) {
			continue;
		}
		PushNotificationTransportTls::SSLCtxUniquePtr ctx{SSL_CTX_new(TLSv1_2_method())};
		if (!ctx) {
			SLOGE << "Could not create ctx!";
			ERR_print_errors_fp(stderr);
			continue;
		}

		if (cafile.empty()) {
			SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);
		} else {
			SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, NULL);
			SSL_CTX_set_cert_verify_callback(ctx.get(), handle_verify_callback, NULL);
		}

		if(! SSL_CTX_load_verify_locations(ctx.get(), cafile.empty()?NULL:cafile.c_str(), "/etc/ssl/certs")) {
			SLOGE << "Error loading trust store";
			ERR_print_errors_fp(stderr);
			continue;
		}

		string certpath = string(certdir) + "/" + cert;
		if (!cert.empty()) {
			int error = SSL_CTX_use_certificate_file(ctx.get(), certpath.c_str(), SSL_FILETYPE_PEM);
			if (error != 1) {
				LOGE("SSL_CTX_use_certificate_file for %s failed: %d", certpath.c_str(), error);
				continue;
			} else if ( isCertExpired(certpath) ){
				LOGEN("Certificate %s is expired! You won't be able to use it for push notifications. Please update your certificate or remove it entirely.", certpath.c_str());
			}
		}
		if (!certpath.empty()) {
			int error = SSL_CTX_use_PrivateKey_file(ctx.get(), certpath.c_str(), SSL_FILETYPE_PEM);
			if (error != 1 || SSL_CTX_check_private_key(ctx.get()) != 1) {
				SLOGE << "Private key does not match the certificate public key for " << certpath << ": " << error;
				continue;
			}
		}

		string certName = cert.substr(0, cert.size() - 4); // Remove .pem at the end of cert
		const char *apn_server = (certName.find(".dev") != string::npos) ? APN_DEV_ADDRESS : APN_PROD_ADDRESS;
		mClients[certName] = make_unique<PushNotificationClient>(
			make_unique<PushNotificationTransportTls>(move(ctx), apn_server, APN_PORT, true),
			cert,
			*this,
			mMaxQueueSize
		);
		SLOGD << "Adding ios push notification client [" << certName << "]";
	}
	closedir(dirp);
}

void PushNotificationService::setupFirebaseClient(const std::map<std::string, std::string> &firebaseKeys) {
	for (const auto &entry : firebaseKeys) {
		const auto &firebaseAppId = entry.first;

		PushNotificationTransportTls::SSLCtxUniquePtr ctx{SSL_CTX_new(SSLv23_client_method())};
		SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, NULL);

		mClients[firebaseAppId] = make_unique<PushNotificationClient>(
			make_unique<PushNotificationTransportTls>(move(ctx), FIREBASE_ADDRESS, FIREBASE_PORT, true),
			"firebase",
			*this,
			mMaxQueueSize
		);
		SLOGD << "Adding firebase push notification client [" << firebaseAppId << "]";
	}
}

void PushNotificationService::setupWindowsPhoneClient(const std::string& packageSID, const std::string& applicationSecret) {
	mWindowsPhonePackageSID = packageSID;
	mWindowsPhoneApplicationSecret = applicationSecret;
	SLOGD << "Adding Windows push notification client for pacakge SID [" << packageSID << "]";
}

} // end of flexisip namespace
