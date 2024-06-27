/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2021  Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <functional>
#include <string>

#include "belle-sip/belle-sip.h"
#include "belle-sip/types.h"

namespace flexisip {

class BellesipUtils {
public:
	using ProcessResponseStatusCb = std::function<void(int status)>;
	using ProcessResponseEventCb = std::function<void(int status, const belle_sip_response_event*)>;
	using ProcessRequestEventCb = std::function<void(const belle_sip_request_event_t*)>;

	BellesipUtils(const std::string& ipaddress,
	              int port,
	              const std::string& transport,
	              const ProcessResponseStatusCb& processResponseStatusCb,
	              const ProcessRequestEventCb& processRequestEventCb);

	BellesipUtils(const std::string& ipaddress,
	              int port,
	              const std::string& transport,
	              const ProcessResponseEventCb& processResponseEventCb,
	              const ProcessRequestEventCb& processRequestEventCb);

	BellesipUtils(const std::string& ipaddress,
	              int port,
	              const std::string& transport,
	              const ProcessResponseStatusCb& processResponseStatusCb);

	~BellesipUtils();
	void sendRawRequest(const std::string& rawMessage, const std::string& rawBody = "");
	void stackSleep(unsigned int milliseconds = 1);
	int getListeningPort();

	belle_sip_provider_t* getProvider();

private:
	belle_sip_stack_t* mStack = nullptr;
	belle_sip_provider_t* mProvider = nullptr;
	belle_sip_listener_t* mListener = nullptr;
	belle_sip_listening_point_t* mListeningPoint = nullptr;

	ProcessResponseStatusCb mProcessResponseStatusCb = nullptr;
	ProcessRequestEventCb mProcessRequestEventCb = nullptr;
	ProcessResponseEventCb mProcessResponseEventCb = nullptr;
};

} // namespace flexisip
