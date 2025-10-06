/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "factory.hh"

#include "async-ctx-creator.hh"
#if ENABLE_REDIS_TLS
#include "tls-async-ctx-creator.hh"
#endif
#include "parameters.hh"

namespace flexisip::redis::async {
std::unique_ptr<AsyncCtxCreatorInterface>
AsyncCtxCreatorFactory::makeAsyncCtxCreator(const ConnectionParameters& params) {
#if ENABLE_REDIS_TLS
	if (params.connectionType != ConnectionType::tcp) return std::make_unique<TlsAsyncCtxCreator>(params);
#endif
	std::ignore = params;
	return std::make_unique<AsyncCtxCreator>();
}

bool AsyncCtxCreatorFactory::isTlsAllowed() {
	return ENABLE_REDIS_TLS;
}

} // namespace flexisip::redis::async