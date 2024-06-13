/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

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
#include "firebase-v1/firebase-v1-client.hh"
#include "firebase/firebase-client.hh"
#include "generic/generic-http-client.hh"
#include "generic/generic-http-request.hh"
#include "generic/generic-http2-client.hh"
#include "utils/transport/tls-connection.hh"

using namespace std;
using namespace filesystem;

namespace flexisip::pushnotification {

const std::string Service::sGenericClientName{"generic"};
const std::string Service::sFallbackClientKey{"fallback"};

Service::Service(const std::shared_ptr<sofiasip::SuRoot>& root, unsigned maxQueueSize)
    : mRoot{root}, mMaxQueueSize{maxQueueSize} {
	SSL_library_init();
	SSL_load_error_strings();
}

Service::~Service() {
	ERR_free_strings();
}

shared_ptr<Client> Service::createAppleClient(const path& caFile, const path& certDir, const path& certFile) {
	auto certName = certFile.stem();
	auto certPath = certDir / certFile;
	try {
		mClients[certName] = make_unique<AppleClient>(*mRoot, caFile, certPath, certName, this);
		SLOGD << "Created iOS push notification client [" << certName << "]";
		return mClients[certName];
	} catch (const TlsConnection::CreationError& err) {
		SLOGW << "Couldn't create iOS push notification client from [" << certName << "]: " << err.what();
		return nullptr;
	}
}

shared_ptr<Client> Service::createAppleClientFromPotentialNewCertificate(const string& certName) {
	const auto& certFile = certName + ".pem";
	for (const auto& certDir : mAppleCertDirs) {
		auto certPath = certDir.first / certFile;
		if (filesystem::exists(certPath)) {
			return createAppleClient(certDir.second, certDir.first, certFile);
		}
	}
	return nullptr;
}

std::shared_ptr<Request> Service::makeRequest(PushType pType, const std::shared_ptr<const PushInfo>& pInfo) {
	// Create a generic request if the generic client has been set.
	auto genericClient = mClients.find(sGenericClientName);
	if (genericClient != mClients.cend() && genericClient->second != nullptr) {
		return genericClient->second->makeRequest(pType, pInfo, mClients);
	}

	// No generic client set, then create a native request for the target platform.
	auto appId = pInfo->getDestination(pType).getAppIdentifier();
	auto client = mClients.find(appId);
	if (client != mClients.cend() && client->second != nullptr) {
		return client->second->makeRequest(pType, pInfo);
	}
	// Check if a certificate is available to create the corresponding client
	if (pInfo->isApple()) {
		auto newClient = createAppleClientFromPotentialNewCertificate(appId);
		if (newClient != nullptr) {
			return newClient->makeRequest(pType, pInfo);
		}
	}
	if (client = mClients.find(sFallbackClientKey); client != mClients.cend() && client->second != nullptr) {
		return client->second->makeRequest(pType, pInfo);
	}
	throw UnavailablePushNotificationClient{pInfo->getDestination(pType)};
}

void Service::sendPush(const std::shared_ptr<Request>& pn) {
	const auto appId = pn->getAppIdentifier();
	auto it = mClients.find(appId);
	auto client = it != mClients.cend() ? it->second : nullptr;
	// Create a client if a corresponding certificate is available
	if (client == nullptr && pn->getPInfo().isApple()) {
		client = createAppleClientFromPotentialNewCertificate(appId);
	}
	if (client == nullptr) {
		it = mClients.find(sFallbackClientKey);
		client = it != mClients.cend() ? it->second : nullptr;
	}
	if (client == nullptr) {
		throw UnavailablePushNotificationClient{pn.get()};
	}
	client->sendPush(pn);
}

bool Service::isIdle() const noexcept {
	return all_of(mClients.cbegin(), mClients.cend(), [](const auto& kv) { return kv.second->isIdle(); });
}

void Service::setupGenericClient(const sofiasip::Url& url, Method method, Protocol protocol) {
	if (method != Method::HttpGet && method != Method::HttpPost) {
		throw UnauthorizedHttpMethod{method};
	}
	if (protocol == Protocol::Http) {
		mClients[sGenericClientName] =
		    GenericHttpClient::makeUnique(url, method, sGenericClientName, mMaxQueueSize, this);
	} else {
		mClients[sGenericClientName] = make_unique<GenericHttp2Client>(url, method, *mRoot, this);
	}
}

void Service::setupiOSClient(const std::string& certDir, const std::string& caFile) {
	filesystem::directory_iterator dirIt;
	try {
		dirIt = filesystem::directory_iterator{certDir};
	} catch (filesystem::filesystem_error& err) {
		SLOGE << "Could not open push notification certificates directory (" << certDir.c_str() << "): " << err.what();
		return;
	}
	mAppleCertDirs[certDir] = caFile;

	SLOGD << "Searching for push notification certificates in directory [" << certDir << "]";

	// Only consider files which end with .pem
	const auto& allowedExtension = ".pem";
	for (const auto& dirEntry : dirIt) {
		const auto& cert = dirEntry.path();
		if (cert.extension() == allowedExtension) createAppleClient(caFile, certDir, cert);
	}
}

void Service::setupFirebaseClients(const GenericStruct* pushConfig) {

	const auto firebaseKeys = pushConfig->get<ConfigStringList>("firebase-projects-api-keys")->read();
	const auto firebaseServiceAccounts = pushConfig->get<ConfigStringList>("firebase-service-accounts")->read();

	// First, add firebase clients indicated in firebase-projects-api-keys.
	for (const auto& keyval : firebaseKeys) {
		size_t sep = keyval.find(":");
		addFirebaseClient(keyval.substr(0, sep), keyval.substr(sep + 1));
	}

	const auto defaultRefreshInterval = chrono::duration_cast<chrono::milliseconds>(
	    chrono::seconds(pushConfig->get<ConfigInt>("firebase-default-refresh-interval")->read()));
	const auto tokenExpirationAnticipationTime = chrono::duration_cast<chrono::milliseconds>(
	    chrono::seconds(pushConfig->get<ConfigInt>("firebase-token-expiration-anticipation-time")->read()));

	// Then, add firebase v1 clients which are indicated in firebase-service-accounts.
	for (const auto& keyval : firebaseServiceAccounts) {
		auto sep = keyval.find(":");

		const auto appId = keyval.substr(0, sep);
		const auto filePath = filesystem::path(keyval.substr(sep + 1));

		if (mClients.find(appId) != mClients.end()) {
			throw runtime_error("unable to add firebase v1 client, firebase application with id \"" + appId +
			                    "\" already exists. Only use firebase-projects-api-keys OR firebase-service-accounts "
			                    "for the same appId.");
		}

		addFirebaseV1Client(appId, filePath, defaultRefreshInterval, tokenExpirationAnticipationTime);
	}
}

void Service::addFirebaseClient(const std::string& appId, const std::string& apiKey) {
	mClients[appId] = make_unique<FirebaseClient>(*mRoot, apiKey, this);
	SLOGD << "Adding firebase push notification client [" << appId << "]";
}

void Service::addFirebaseV1Client(const std::string& appId,
                                  const std::filesystem::path& serviceAccountFilePath,
                                  const std::chrono::milliseconds& defaultRefreshInterval,
                                  const std::chrono::milliseconds& tokenExpirationAnticipationTime) {

	mClients[appId] =
	    make_unique<FirebaseV1Client>(*mRoot,
	                                  make_shared<FirebaseV1AuthenticationManager>(
	                                      mRoot, FIREBASE_GET_ACCESS_TOKEN_SCRIPT_PATH, serviceAccountFilePath,
	                                      defaultRefreshInterval, tokenExpirationAnticipationTime),
	                                  this);
	SLOGD << "Adding firebase push notification client [" << appId << "]";
}

void Service::setFallbackClient(const std::shared_ptr<Client>& fallbackClient) {
	if (fallbackClient) fallbackClient->mService = this;
	mClients[sFallbackClientKey] = fallbackClient;
}

} // namespace flexisip::pushnotification
