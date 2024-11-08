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

#pragma once

#include <memory>

#include <linphone++/call.hh>
#include <linphone++/enums.hh>

#include "utils/client-builder.hh"

namespace flexisip::tester {

class CoreClient;
class ClientCall;

class CallBuilder {
public:
	explicit CallBuilder(const CoreClient&);

	const CallBuilder& setEarlyMediaSending(OnOff) const;
	const CallBuilder& setVideo(OnOff) const;
	std::optional<ClientCall> call(const std::string&) const;

private:
	const CoreClient& mClient;
	const std::shared_ptr<linphone::CallParams> mParams;
};

} // namespace flexisip::tester