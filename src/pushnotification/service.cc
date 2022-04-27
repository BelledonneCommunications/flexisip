/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

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

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <flexisip/common.hh>

#include "apple/apple-client.hh"
#include "firebase/firebase-client.hh"
#include "microsoftpush.hh"
#include "wp-client.hh"

#include "service.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

static constexpr const char* WPPN_PORT = "443";

Service::Service(su_root_t& root, unsigned maxQueueSize) : mRoot{root}, mMaxQueueSize{maxQueueSize} {
	SSL_library_init();
	SSL_load_error_strings();
}

Service::~Service() {
	ERR_free_strings();
}

std::unique_ptr<Request> Service::makePushRequest(const PushInfo& pinfo) {
	if (pinfo.mType == "apple") return make_unique<AppleRequest>(pinfo);
	if (pinfo.mType == "firebase") return make_unique<FirebaseRequest>(pinfo);
	if (pinfo.mType == "wp" || pinfo.mType == "wp10") return make_unique<WindowsPhoneRequest>(pinfo);
	throw invalid_argument("invalid service type [" + pinfo.mType + "]");
}

int Service::sendPush(const std::shared_ptr<Request>& pn) {
	auto client = mClients[pn->getAppIdentifier()].get();
	if (client == nullptr) {
		auto isW10 = (pn->getType() == "w10");
		auto isWP = (pn->getType() == "wp");
		if (isW10 || isWP) {
			// In Windows case we can't create all push notification clients at start up since we need to wait the
			// registration of all AppID Therefore we create the push notification client just before sending the push.
			if (isW10 && (mWindowsPhonePackageSID.empty() || mWindowsPhoneApplicationSecret.empty())) {
				SLOGE << "Windows Phone not configured for push notifications ("
				         "package sid is "
				      << (mWindowsPhonePackageSID.empty() ? "NOT configured" : "configured") << " and "
				      << "application secret is "
				      << (mWindowsPhoneApplicationSecret.empty() ? "NOT configured" : "configured") << ").";
				return -1;
			} else {
				auto wpClient = pn->getAppIdentifier();

				LOGD("Creating PN client for %s", pn->getAppIdentifier().c_str());
				if (isW10) {
					auto conn = make_unique<TlsConnection>(pn->getAppIdentifier(), WPPN_PORT);
					mClients[wpClient] =
					    make_unique<ClientWp>(make_unique<TlsTransport>(move(conn)), wpClient, mMaxQueueSize,
					                          mWindowsPhonePackageSID, mWindowsPhoneApplicationSecret, this);
				} else {
					auto conn = make_unique<TlsConnection>(pn->getAppIdentifier(), "80", "", "");
					mClients[wpClient] =
					    make_unique<LegacyClient>(make_unique<TlsTransport>(move(conn)), wpClient, mMaxQueueSize, this);
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

bool Service::isIdle() const noexcept {
	for (const auto& entry : mClients) {
		if (!entry.second->isIdle()) return false;
	}
	return true;
}

void Service::setupGenericClient(const url_t* url) {
	unique_ptr<TlsConnection> conn;
	if (url->url_type == url_https) {
		conn = make_unique<TlsConnection>(url->url_host, url_port(url));
	} else {
		conn = make_unique<TlsConnection>(url->url_host, url_port(url), "", "");
	}

	mClients["generic"] =
	    make_unique<LegacyClient>(make_unique<TlsTransport>(move(conn)), "generic", mMaxQueueSize, this);
}

void Service::setupiOSClient(const std::string& certdir, const std::string& cafile) {
	struct dirent* dirent;
	DIR* dirp;

	dirp = opendir(certdir.c_str());
	if (dirp == NULL) {
		LOGE("Could not open push notification certificates directory (%s): %s", certdir.c_str(), strerror(errno));
		return;
	}
	SLOGD << "Searching push notification client on dir [" << certdir << "]";

	while (true) {
		errno = 0;
		if ((dirent = readdir(dirp)) == NULL) {
			if (errno) {
				SLOGE << "Cannot read dir [" << certdir << "] because [" << strerror(errno) << "]";
			}
			break;
		}

		string cert = string(dirent->d_name);
		// only consider files which end with .pem
		string suffix = ".pem";
		if (cert.compare(".") == 0 || cert.compare("..") == 0 || cert.length() <= suffix.length() ||
		    (cert.compare(cert.length() - suffix.length(), suffix.length(), suffix) != 0)) {
			continue;
		}
		string certpath = string(certdir) + "/" + cert;
		string certName = cert.substr(0, cert.size() - 4); // Remove .pem at the end of cert
		mClients[certName] = make_unique<AppleClient>(mRoot, cafile, certpath, certName, this);
		SLOGD << "Adding ios push notification client [" << certName << "]";
	}
	closedir(dirp);
}

void Service::setupFirebaseClient(const std::map<std::string, std::string>& firebaseKeys) {
	for (const auto& entry : firebaseKeys) {
		const auto& firebaseAppId = entry.first;

		mClients[firebaseAppId] = make_unique<FirebaseClient>(mRoot, this);
		SLOGD << "Adding firebase push notification client [" << firebaseAppId << "]";
	}
}

void Service::setupWindowsPhoneClient(const std::string& packageSID, const std::string& applicationSecret) {
	mWindowsPhonePackageSID = packageSID;
	mWindowsPhoneApplicationSecret = applicationSecret;
	SLOGD << "Adding Windows push notification client for pacakge SID [" << packageSID << "]";
}

} // namespace pushnotification
} // namespace flexisip
