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

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace flexisip {

struct SSLCtxDeleter {
	void operator()(SSL_CTX* ssl) const {
		SSL_CTX_free(ssl);
	}
};

struct BIODeleter {
	void operator()(BIO* bio) const {
		BIO_free_all(bio);
	}
};

struct SSLDeleter {
	void operator()(SSL* ssl) const {
		SSL_free(ssl);
	}
};

using SSLCtxUniquePtr = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;
using BIOUniquePtr = std::unique_ptr<BIO, BIODeleter>;
using SSLUniquePtr = std::unique_ptr<SSL, SSLDeleter>;

std::string formatBioError(const std::string& msg, long status);
std::optional<std::string> sslLoop(const BIOUniquePtr& bio,
                                   const std::function<int(BIO&)>& func,
                                   std::chrono::milliseconds timeout,
                                   const std::string& errmsg) noexcept;

/**
 * Actively wait for connection completion and check the certificate.
 */
std::optional<std::string> waitForSslHandshakeAndCheckCertificate(const BIOUniquePtr& bioPtr,
                                                                  const SSL* ssl,
                                                                  std::chrono::milliseconds timeout,
                                                                  const std::string& handshakeErrMsg);

/**
 * Add a Server Name Indication (SNI) to the SSL context.
 *
 * > Currently, the only server names supported are DNS hostnames;
 * https://www.rfc-editor.org/rfc/rfc6066#section-3
 *
 * A DNS hostname must follow the syntax described in https://www.rfc-editor.org/rfc/rfc1034#section-3.5 and therefore
 * cannot contain e.g. ':' (to append the port)
 *
 * @param[in] serverName either an IP address (in which case, no SNI is added) or a DNS hostname (roughly, a subset of
 * all the strings matching regex [a-z0-9\.-])
 */
long setSNI(SSL* ssl, const std::string& serverName);

void setSSLOptions(SSL* ssl, bool mustBeHttp2);

} // namespace flexisip
