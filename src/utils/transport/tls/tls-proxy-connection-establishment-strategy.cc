/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "tls-proxy-connection-establishment-strategy.hh"

#include <cmath>

#include <openssl/err.h>

#include "bctoolbox/crypto.h"

#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {

TlsProxyConnectionEstablishmentStrategy::TlsProxyConnectionEstablishmentStrategy(const HttpsProxyCfg& httpsProxyCfg)
    : mHttpsProxyCfg(httpsProxyCfg),
      mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsProxyConnectionEstablishmentStrategy")} {}

std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>>
TlsProxyConnectionEstablishmentStrategy::connect(SSLCtxUniquePtr& context,
                                                 const string& host,
                                                 const string& port,
                                                 const bool mustBeHttp2,
                                                 const chrono::milliseconds timeout) noexcept {
	auto hostport = mHttpsProxyCfg.getHost() + ":" + std::to_string(mHttpsProxyCfg.getPort());
	// Keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revisions of OpenSSL.
	auto proxyBio = BIOUniquePtr{BIO_new_connect(const_cast<char*>(hostport.c_str()))};
	BIO_set_nbio(proxyBio.get(), 1);

	// Ensure that the error queue is empty
	ERR_clear_error();

	// Do the connection by actively waiting for connection completion
	if (auto result = sslLoop(
	        proxyBio, [](BIO& bio) { return BIO_do_connect(&bio); }, timeout,
	        "Error while connecting to tcp://" + hostport);
	    result.has_value()) {
		LOGE << result.value();
		return nullopt;
	}

	LOGD << "Connected to HTTPS proxy " << hostport;

	int statusCode = 0;
	if (connectRequestToHttpsProxy(proxyBio, host, port, timeout, statusCode, false) < 0) {
		return nullopt;
	}

	// Check HTTPS proxy response
	switch (statusCode) {
		case 200:
			// Tunnel has been created, continue with SSL handshake
			break;
		case 407:
			LOGD << "HTTPS proxy requires authentication";
			statusCode = 0;
			if (connectRequestToHttpsProxy(proxyBio, host, port, timeout, statusCode, true) < 0) {
				return nullopt;
			}
			if (statusCode == 200) {
				// Tunnel has been created, continue with SSL handshake
			} else {
				LOGE << "HTTPS proxy returned error code " << statusCode;
				return nullopt;
			}
			break;
		default:
			LOGE << "HTTPS proxy returned error code " << statusCode;
			return nullopt;
	}

	auto ssl = SSLUniquePtr{SSL_new(context.get())};
	setSNI(ssl.get(), host);
	setSSLOptions(ssl.get(), mustBeHttp2);
	SSL_set_connect_state(ssl.get());
	SSL_set_bio(ssl.get(), proxyBio.get(), proxyBio.get());
	proxyBio.release();
	auto newBio = BIOUniquePtr{BIO_new(BIO_f_ssl())};
	BIO_set_ssl(newBio.get(), ssl.get(), BIO_NOCLOSE);
	const auto errmsg = "Error while performing SSL handshake for tls://"s + hostport;
	if (const auto error = waitForSslHandshakeAndCheckCertificate(newBio, ssl.get(), timeout, errmsg);
	    error.has_value()) {
		LOGE << error.value();
		return nullopt;
	}

	return std::make_pair(std::move(newBio), std::move(ssl));
}

int TlsProxyConnectionEstablishmentStrategy::connectRequestToHttpsProxy(const BIOUniquePtr& bio,
                                                                        const string& host,
                                                                        const string& port,
                                                                        chrono::milliseconds timeout,
                                                                        int& statusCode,
                                                                        const bool authentication) noexcept {
	char buf[4096] = {};
	size_t readBytes = 0;
	ostringstream connectOss;
	connectOss << "CONNECT " << host << ":" << port << " HTTP/1.1\r\nHost: " << host << "\r\n";
	if (authentication) {
		const auto username = mHttpsProxyCfg.getUsername();
		const auto password = mHttpsProxyCfg.getPassword();
		if (username.empty() || password.empty()) {
			LOGE
			    << "HTTPS proxy requires authentication, but no username or password was provided in the configuration";
			return -1;
		}
		string credentials{username + ":" + password};
		credentials = base64Encode(credentials);
		connectOss << "Proxy-Authorization: Basic " << credentials << "\r\n";
	}
	connectOss << "\r\n";
	const auto connectStr = connectOss.str();
	if (BIO_write(bio.get(), connectStr.c_str(), static_cast<int>(connectStr.length())) <= 0) {
		LOGE << "Error while sending CONNECT request to HTTPS proxy";
		return -1;
	}
	if (auto result = sslLoop(
	        bio, [&buf, &readBytes](BIO& bio) { return BIO_read_ex(&bio, buf, sizeof(buf), &readBytes); }, timeout,
	        "Error while reading CONNECT response from HTTPS proxy");
	    result.has_value()) {
		LOGE << result.value();
		return -1;
	}

	const string responseProtocol(buf, 9);
	if (readBytes < 12 || responseProtocol != "HTTP/1.1 ") {
		LOGE << "Invalid CONNECT response from HTTPS proxy";
		return -1;
	}
	const string statusCodeStr(buf + 9, 3);
	statusCode = 0;
	try {
		statusCode = stoi(statusCodeStr);
	} catch (const std::invalid_argument&) {
		LOGE << "Invalid status code ('" << statusCodeStr << "') in CONNECT response from HTTPS proxy";
		return -1;
	}

	return 0;
}

std::string TlsProxyConnectionEstablishmentStrategy::base64Encode(const string& input) noexcept {
	const auto tokenSize = input.size();
	auto encodedTokenSize = static_cast<size_t>(ceil(((4 * tokenSize) + 2) / 3) + 5);
	std::vector<uint8_t> token(tokenSize);
	memcpy(token.data(), input.data(), input.size());
	std::vector<uint8_t> encodedToken(encodedTokenSize);
	bctbx_base64_encode(encodedToken.data(), &encodedTokenSize, token.data(), token.size());
	return {encodedToken.data(), encodedToken.data() + encodedTokenSize};
};

} // namespace flexisip