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

#include "flexisip/event.hh"

#include <memory>

#include "flexisip/logmanager.hh"
#include "transaction/incoming-agent.hh"
#include "transaction/outgoing-agent.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {
namespace {

class OutgoingAgentMock : public OutgoingAgent {
public:
	OutgoingAgentMock() = default;
	OutgoingAgentMock(const OutgoingAgentMock&) = delete;
	~OutgoingAgentMock() override = default;

	void send(const std::shared_ptr<MsgSip>&,
	          url_string_t const*,
	          RequestSipEvent::BeforeSendCallbackList&&,
	          tag_type_t,
	          tag_value_t,
	          ...) override {
		BC_HARD_FAIL("should not be called");
	}
	std::weak_ptr<Agent> getAgent() noexcept override {
		return weak_ptr<Agent>{};
	}
};

class IncomingAgentMock : public IncomingAgent {
public:
	IncomingAgentMock() = default;
	IncomingAgentMock(const IncomingAgentMock&) = delete;
	~IncomingAgentMock() override = default;

	void send(const std::shared_ptr<MsgSip>&, url_string_t const*, tag_type_t, tag_value_t, ...) override {
		BC_HARD_FAIL("should not be called");
	}
	void reply(const std::shared_ptr<MsgSip>&, int, char const*, tag_type_t, tag_value_t, ...) override {
		BC_HARD_FAIL("should not be called");
	}
	std::weak_ptr<Agent> getAgent() noexcept override {
		return weak_ptr<Agent>{};
	}
};

shared_ptr<MsgSip> getMsgSip() {
	const auto response =
	    "SIP/2.0 200 Ok\r\n"
	    "Via: SIP/2.0/TCP localhost;received=127.0.0.1;branch=z9hG4bK.NcSyjy6Zm23N38HmBQ1Havmp7e;rport=42211\r\n"
	    "Via: SIP/2.0/TLS [2a01:cb1d:8c59:4200:4fe9:f372:94b6:5443]:54588;branch=z9hG4bK.9o3Kyi223;rport=54588\r\n"
	    "From: <sip:caller@flexisip-staging.linphone.org>;tag=0pX5HuPmV\r\n"
	    "To: <sip:callee@flexisip-staging.linphone.org>;tag=sLypEpy\r\n"
	    "Call-ID: F3ryNU02Zh\r\n"
	    "CSeq: 21 PUBLISH\r\n"
	    "SIP-ETag: DxihcWD\r\n"
	    "Expires: 120\r\n"
	    "Content-Length: 0"s;

	return make_shared<MsgSip>(0, response);
}

void doNotForwardTest() {
	const auto outgoingMock = make_shared<OutgoingAgentMock>();
	const auto incomingMock = make_shared<IncomingAgentMock>();
	ResponseSipEvent responseSipEvent{outgoingMock, getMsgSip()};
	responseSipEvent.setIncomingAgent(incomingMock);

	responseSipEvent.doNotForward();

	responseSipEvent.send(responseSipEvent.getMsgSip());
}

TestSuite _{
    "ResponseSipEvent",
    {
        CLASSY_TEST(doNotForwardTest),
    },
};

} // namespace
} // namespace flexisip::tester