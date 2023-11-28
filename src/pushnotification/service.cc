/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "service.hh"

#include <sstream>

#include <dirent.h>

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <flexisip/common.hh>

#include "apple/apple-client.hh"
#include "firebase/firebase-client.hh"
#include "generic/generic-http-client.hh"
#include "generic/generic-http2-client.hh"
#include "pushnotification/apple/apple-request.hh"
#include "pushnotification/firebase/firebase-request.hh"
#include "pushnotification/generic/generic-http-request.hh"
#include "utils/transport/tls-connection.hh"

using namespace std;

namespace flexisip {
namespace pushnotification {

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
		return genericClient->second->makeRequest(pType, pInfo, mClients);
	}

	// No generic client set, then create a native request for the target platform.
	auto client = mClients.find(pInfo->getDestination(pType).getAppIdentifier());
	if (client != mClients.cend() && client->second != nullptr) {
		return client->second->makeRequest(pType, pInfo);
	} else if (client = mClients.find(sFallbackClientKey); client != mClients.cend() && client->second != nullptr) {
		return client->second->makeRequest(pType, pInfo);
	} else {
		throw runtime_error{"No PN client available for AppID[" + pInfo->getDestination(pType).getAppIdentifier() +
		                    "]"};
	}
}

void Service::sendPush(const std::shared_ptr<Request>& pn) {
	auto it = mClients.find(pn->getAppIdentifier());
	auto client = it != mClients.cend() ? it->second.get() : nullptr;
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

void Service::setupGenericClient(const sofiasip::Url& url, Method method, Protocol protocol) {
	if (method != Method::HttpGet && method != Method::HttpPost) {
		ostringstream msg{};
		msg << "invalid method value [" << static_cast<int>(method) << "]. Only HttpGet and HttpPost are authorized";
		throw invalid_argument{msg.str()};
	}
	if (protocol == Protocol::Http) {
		mClients[sGenericClientName] =
		    GenericHttpClient::makeUnique(url, method, sGenericClientName, mMaxQueueSize, this);
	} else {
		mClients[sGenericClientName] = make_unique<GenericHttp2Client>(url, method, mRoot, this);
	}
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
		try {
			mClients[certName] = make_unique<AppleClient>(mRoot, cafile, certpath, certName, this);
			SLOGD << "Adding ios push notification client [" << certName << "]";
		} catch (const TlsConnection::CreationError& err) {
			SLOGW << "Couldn't make iOS PN client from [" << certName << "]: " << err.what();
		}
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

void Service::setFallbackClient(const std::shared_ptr<Client>& fallbackClient) {
	if (fallbackClient) fallbackClient->mService = this;
	mClients[sFallbackClientKey] = fallbackClient;
}

} // namespace pushnotification
} // namespace flexisip
