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

#include "utils/transport/http/https-proxy-cfg.hh"

#include "tls-connection-establishment-strategy.hh"

namespace flexisip {

/**
 * Implementation of a TLS (via HTTPS proxy) connection establishment strategy over the OpenSSL library.
 */
class TlsProxyConnectionEstablishmentStrategy : public TlsConnectionEstablishmentStrategy {
public:
	explicit TlsProxyConnectionEstablishmentStrategy(const HttpsProxyCfg& httpsProxyCfg);

	std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>> connect(SSLCtxUniquePtr& context,
	                                                             const std::string& host,
	                                                             const std::string& port,
	                                                             bool mustBeHttp2,
	                                                             std::chrono::milliseconds timeout) noexcept override;

private:
	static std::string base64Encode(const std::string& input) noexcept;

	int connectRequestToHttpsProxy(const BIOUniquePtr& bio,
	                               const std::string& host,
	                               const std::string& port,
	                               std::chrono::milliseconds timeout,
	                               int& statusCode,
	                               bool authentication = false) noexcept;

	HttpsProxyCfg mHttpsProxyCfg;
	std::string mLogPrefix{};
};

} // namespace flexisip