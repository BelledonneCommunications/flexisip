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

#include "generic-http-client.hh"

#include "generic-http-request.hh"
#include "generic-utils.hh"
#include "pushnotification/push-notification-exceptions.hh"

using namespace std;

namespace flexisip::pushnotification {

GenericHttpClient::GenericHttpClient(std::unique_ptr<Transport>&& transport,
                                     const std::string& name,
                                     unsigned maxQueueSize,
                                     const Service* service)
    : LegacyClient(std::move(transport), name, maxQueueSize, service) {
}

std::unique_ptr<GenericHttpClient> GenericHttpClient::makeUnique(
    const sofiasip::Url& url, Method method, const string& name, unsigned int maxQueueSize, const Service* service) {
	if (method != Method::HttpGet && method != Method::HttpPost) {
		throw UnauthorizedHttpMethod{method};
	}

	unique_ptr<TlsConnection> conn{};
	if (url.getType() == url_https) {
		conn = make_unique<TlsConnection>(url.getHost(), url.getPort(true));
	} else {
		conn = make_unique<TlsConnection>(url.getHost(), url.getPort(true), "", "");
	}

	return make_unique<GenericHttpClient>(make_unique<TlsTransport>(std::move(conn), method, url), name, maxQueueSize,
	                                      service);
}

std::shared_ptr<Request>
GenericHttpClient::makeRequest(PushType pType,
                               const std::shared_ptr<const PushInfo>& pInfo,
                               const std::map<std::string, std::shared_ptr<Client>>& allClients) {
	auto request = make_shared<GenericHttpRequest>(pType, pInfo);

	// Set the authentication key in case the native PNR is for the Firebase service.
	request->setFirebaseAuthKey(GenericUtils::getFirebaseAuthKey(pType, pInfo, allClients));

	return request;
}

} // namespace flexisip::pushnotification
