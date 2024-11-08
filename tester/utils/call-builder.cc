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

#include "call-builder.hh"

#include <string>

#include "utils/client-builder.hh"
#include "utils/client-call.hh"
#include "utils/client-core.hh"

namespace flexisip::tester {

CallBuilder::CallBuilder(const CoreClient& client)
    : mClient(client), mParams(mClient.getCore()->createCallParams(nullptr)) {
}

std::optional<ClientCall> CallBuilder::call(const std::string& destination) const {
	return ClientCall::tryFrom(mClient.invite(destination, mParams));
}

const CallBuilder& CallBuilder::setEarlyMediaSending(OnOff enabled) const {
	mParams->enableEarlyMediaSending(bool(enabled));
	return *this;
}

const CallBuilder& CallBuilder::setVideo(OnOff enabled) const {
	mParams->enableVideo(bool(enabled));
	return *this;
}

} // namespace flexisip::tester