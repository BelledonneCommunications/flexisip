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

#include "tls-connection-utils.hh"

#include <chrono>
#include <thread>

#include <openssl/err.h>

#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {

string formatBioError(const string& msg, const long status) {
	ostringstream ss;
	ss << msg << " (status = " << status << "), errno = " << strerror(errno);
	string sslErrorStack{};
	ERR_print_errors_cb(
	    [](const char* str, size_t, void* u) {
		    if (str == nullptr) return 0;
		    auto& error = *static_cast<string*>(u);
		    error = str;
		    return 0;
	    },
	    &sslErrorStack);
	if (!sslErrorStack.empty()) {
		ss << endl << "SSL error stack: " << sslErrorStack;
	}
	return ss.str();
}

optional<string> sslLoop(const BIOUniquePtr& bio,
                         const function<int(BIO&)>& func,
                         const chrono::milliseconds timeout,
                         const string& errmsg) noexcept {
	auto status = 0;
	chrono::milliseconds time{0};
	while (status <= 0) {
		status = func(*bio.get());
		if (status <= 0 && !BIO_should_retry(bio.get())) {
			return formatBioError(errmsg, status);
		}
		if (time >= timeout) {
			return "Timeout: " + errmsg;
		}

		constexpr chrono::milliseconds sleepDuration{10};
		this_thread::sleep_for(sleepDuration);
		time += sleepDuration;
	}
	return nullopt;
}

optional<string> waitForSslHandshakeAndCheckCertificate(const BIOUniquePtr& bioPtr,
                                                        const SSL* ssl,
                                                        const chrono::milliseconds timeout,
                                                        const string& handshakeErrMsg) {
	if (auto result = sslLoop(
	        bioPtr, [](BIO& bio) { return BIO_do_handshake(&bio); }, timeout, handshakeErrMsg);
	    result.has_value()) {
		return result;
	}

	if (ssl && (SSL_get_verify_mode(ssl) == SSL_VERIFY_PEER && SSL_get_verify_result(ssl) != X509_V_OK)) {
		return "Certificate verification error: " + string(X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
	}

	return nullopt;
}

long setSNI(SSL* ssl, const string& serverName) {
	const auto* serverNameCStr = serverName.c_str();
	// Connecting to an IP address cannot be ambiguous, so not only is there no need to provide an SNI, but furthermore:
	// > Literal IPv4 and IPv6 addresses are not permitted in "HostName".
	// https://www.rfc-editor.org/rfc/rfc6066#section-3
	if (uri_utils::isIpAddress(serverNameCStr)) return 0L;

	return SSL_set_tlsext_host_name(ssl, serverNameCStr);
}

void setSSLOptions(SSL* ssl, const bool mustBeHttp2) {
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_options(ssl, SSL_OP_ALL);
	if (mustBeHttp2) {
		constexpr unsigned char protos[] = {2, 'h', '2'};
		constexpr unsigned int protos_len = sizeof(protos);
		SSL_set_alpn_protos(ssl, protos, protos_len);
	}
}

} // namespace flexisip
