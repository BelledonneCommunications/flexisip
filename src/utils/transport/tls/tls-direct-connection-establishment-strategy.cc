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

#include "tls-direct-connection-establishment-strategy.hh"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "flexisip/logmanager.hh"

using namespace std;

namespace flexisip {

TlsDirectConnectionEstablishmentStrategy::TlsDirectConnectionEstablishmentStrategy()
    : mLogPrefix{LogManager::makeLogPrefixForInstance(this, "TlsDirectConnectionEstablishmentStrategy")} {}

std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>>
TlsDirectConnectionEstablishmentStrategy::connect(SSLCtxUniquePtr& context,
                                                  const std::string& host,
                                                  const std::string& port,
                                                  bool mustBeHttp2,
                                                  const chrono::milliseconds timeout) noexcept {
	const auto hostport = host + ":" + port;
	SSL* ssl = nullptr;

	BIOUniquePtr newBio{};
	if (context != nullptr) {
		newBio = BIOUniquePtr{BIO_new_ssl_connect(context.get())};
		BIO_set_conn_hostname(newBio.get(), hostport.c_str());
		BIO_get_ssl(newBio.get(), &ssl);
		setSNI(ssl, host);
		setSSLOptions(ssl, mustBeHttp2);
	} else {
		// keep the const_cast() here because BIO_new_connect() takes a 'char *' in old revisions of OpenSSL.
		newBio = BIOUniquePtr{BIO_new_connect(const_cast<char*>(hostport.c_str()))};
	}
	BIO_set_nbio(newBio.get(), 1);

	// Ensure that the error queue is empty
	ERR_clear_error();

	const auto proto = (context != nullptr) ? "tls://" : "tcp://";
	const auto errmsg = "Error while connecting to "s + proto + hostport;
	if (const auto error = waitForSslHandshakeAndCheckCertificate(newBio, ssl, timeout, errmsg); error.has_value()) {
		LOGE << error.value();
		return nullopt;
	}

	return std::make_pair(std::move(newBio), nullptr);
}

} // namespace flexisip