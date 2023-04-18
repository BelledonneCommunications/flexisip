/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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
#include "legacy/genericpush.hh"
#include "legacy/microsoftpush.hh"
#include "legacy/wp-client.hh"

#include "service.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

static constexpr const char* WPPN_PORT = "443";
const std::string Service::sGenericClientName{"generic"};
const std::string Service::sFallbackClientKey{"fallback"};

Service::Service(sofiasip::SuRoot& root, unsigned maxQueueSize) : mRoot{root}, mMaxQueueSize{maxQueueSize} {
	SSL_library_init();
	SSL_load_error_strings();
}

Service::~Service() {
	ERR_free_strings();
}

std::shared_ptr<Request> Service::makeRequest(PushType pType, const std::shared_ptr<const PushInfo>& pInfo) const {
	// Create a generic request if the generic client has been set.
	auto genericClient = mClients.find(sGenericClientName);
	if (genericClient != mClients.cend() && genericClient->second != nullptr) {
		return makeGenericRequest(pType, pInfo);
	}

	// No generic client set, then create a native request for the target platform.
	const auto& provider = pInfo->getPNProvider();
	if (provider == "apns" || provider == "apns.dev") {
		return make_shared<AppleRequest>(pType, pInfo);
	} else if (provider == "fcm") {
		return make_shared<FirebaseRequest>(pType, pInfo);
	} else if (provider == "wp") {
		return make_shared<WindowsPhoneRequest>(pType, pInfo);
	} else if (provider == "w10") {
		return make_shared<Windows10Request>(pType, pInfo);
	} else {
		throw runtime_error{"unsupported PN provider [" + provider + "]"};
	}
}

void Service::sendPush(const std::shared_ptr<Request>& pn) {
	auto it = mClients.find(pn->getAppIdentifier());
	auto client = it != mClients.cend() ? it->second.get() : nullptr;
	if (client == nullptr) {
		if (auto microsoftReq = dynamic_pointer_cast<MicrosoftRequest>(pn)) {
			client = createWindowsClient(microsoftReq);
		}
	}
	if (client == nullptr) {
		it = mClients.find(sFallbackClientKey);
		client = it != mClients.cend() ? it->second.get() : nullptr;
	}
	if (client == nullptr) {
		ostringstream os{};
		os << "No push notification client available for push notification request : " << pn;
		throw runtime_error{os.str()};
	}
	client->sendPush(pn);
}

bool Service::isIdle() const noexcept {
	return all_of(mClients.cbegin(), mClients.cend(), [](const auto& kv) { return kv.second->isIdle(); });
}

void Service::setupGenericClient(const sofiasip::Url& url, Method method) {
	if (method != Method::HttpGet && method != Method::HttpPost) {
		ostringstream msg{};
		msg << "invalid method value [" << static_cast<int>(method) << "]. Only HttpGet and HttpPost are authorized";
		throw invalid_argument{msg.str()};
	}

	unique_ptr<TlsConnection> conn{};
	if (url.getType() == url_https) {
		conn = make_unique<TlsConnection>(url.getHost(), url.getPort(true));
	} else {
		conn = make_unique<TlsConnection>(url.getHost(), url.getPort(true), "", "");
	}

	mClients[sGenericClientName] = make_unique<LegacyClient>(make_unique<TlsTransport>(move(conn), method, url),
	                                                         sGenericClientName, mMaxQueueSize, this);
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

void Service::setupFirebaseClients(const std::list<std::string>& firebaseKeys) {
	for (auto it = firebaseKeys.cbegin(); it != firebaseKeys.cend(); ++it) {
		const string& keyval = *it;
		size_t sep = keyval.find(":");
		addFirebaseClient(keyval.substr(0, sep), keyval.substr(sep + 1));
	}
}

void Service::addFirebaseClient(const std::string& appId, const std::string& apiKey) {
	mClients[appId] = make_unique<FirebaseClient>(mRoot, apiKey, this);
	SLOGD << "Adding firebase push notification client [" << appId << "]";
}

void Service::setupWindowsPhoneClient(const std::string& packageSID, const std::string& applicationSecret) {
	mWindowsPhonePackageSID = packageSID;
	mWindowsPhoneApplicationSecret = applicationSecret;
	SLOGD << "Adding Windows push notification client for pacakge SID [" << packageSID << "]";
}

void Service::setFallbackClient(const std::shared_ptr<Client>& fallbackClient) {
	if (fallbackClient) fallbackClient->mService = this;
	mClients[sFallbackClientKey] = fallbackClient;
}

Client* Service::createWindowsClient(const std::shared_ptr<MicrosoftRequest>& pnImpl) {
	auto isW10 = (dynamic_pointer_cast<Windows10Request>(pnImpl) != nullptr);

	// In Windows case we can't create all push notification clients at start up since we need to wait the registration
	// of all AppID Therefore we create the push notification client just before sending the push.
	if (isW10 && (mWindowsPhonePackageSID.empty() || mWindowsPhoneApplicationSecret.empty())) {
		ostringstream msg{};
		msg << "Windows Phone not configured for push notifications ("
		       "package sid is "
		    << (mWindowsPhonePackageSID.empty() ? "NOT configured" : "configured") << " and "
		    << "application secret is " << (mWindowsPhoneApplicationSecret.empty() ? "NOT configured" : "configured")
		    << ").";
		throw runtime_error{msg.str()};
	}
	const auto& wpClient = pnImpl->getAppIdentifier();
	LOGD("Creating PN client for %s", pnImpl->getAppIdentifier().c_str());
	auto& client = mClients[wpClient];
	if (isW10) {
		auto conn = make_unique<TlsConnection>(pnImpl->getAppIdentifier(), WPPN_PORT);
		client = make_unique<ClientWp>(make_unique<TlsTransport>(move(conn)), wpClient, mMaxQueueSize,
		                               mWindowsPhonePackageSID, mWindowsPhoneApplicationSecret, this);
	} else {
		auto conn = make_unique<TlsConnection>(pnImpl->getAppIdentifier(), "80", "", "");
		client = make_unique<LegacyClient>(make_unique<TlsTransport>(move(conn)), wpClient, mMaxQueueSize, this);
	}
	return client.get();
}

std::shared_ptr<GenericRequest> Service::makeGenericRequest(PushType pType,
                                                            const std::shared_ptr<const PushInfo>& pInfo) const {
	auto request = make_shared<GenericRequest>(pType, pInfo);

	// Set the authentication key in case the native PNR is for the Firebase service.
	const auto& destination = request->getDestination();
	if (destination.getProvider() == "fcm") {
		const auto& projectID = destination.getParam();
		auto it = mClients.find(projectID);
		// The client may not exist if 'module::PushNotification/firebase' parameter is 'false', which isn't
		// unusual in GenericPush use case.
		if (it != mClients.end()) {
			const auto& client = dynamic_pointer_cast<FirebaseClient>(it->second);
			request->setFirebaseAuthKey(client->getApiKey());
		}
	}

	return request;
}

} // namespace pushnotification
} // namespace flexisip
