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

#include "tls-connection-establishment-strategy.hh"

namespace flexisip {

/**
 * Implementation of a direct TLS connection establishment strategy over the OpenSSL library.
 */
class TlsDirectConnectionEstablishmentStrategy : public TlsConnectionEstablishmentStrategy {
public:
	TlsDirectConnectionEstablishmentStrategy();

	std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>> connect(SSLCtxUniquePtr& context,
	                                                             const std::string& host,
	                                                             const std::string& port,
	                                                             bool mustBeHttp2,
	                                                             std::chrono::milliseconds timeout) noexcept override;

private:
	std::string mLogPrefix{};
};

} // namespace flexisip