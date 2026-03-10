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
#include <optional>
#include <utility>

#include "tls-connection-utils.hh"

namespace flexisip {

class TlsConnectionEstablishmentStrategy {
public:
	virtual ~TlsConnectionEstablishmentStrategy() = default;

	virtual std::optional<std::pair<BIOUniquePtr, SSLUniquePtr>>
	connect(SSLCtxUniquePtr& context,
	        const std::string& host,
	        const std::string& port,
	        bool mustBeHttp2,
	        std::chrono::milliseconds timeout) noexcept = 0;
};

} // namespace flexisip
