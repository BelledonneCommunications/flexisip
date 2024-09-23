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

#include <chrono>
#include <string>

#include "registrardb-internal.hh"
#include "sofia-sip/su_time.h"
#include "transaction/outgoing-transaction.hh"
#include "utils/bellesip-utils.hh"
#include "utils/core-assert.hh"
#include "utils/override-static.hh"
#include "utils/proxy-server.hh"
#include "utils/test-patterns/registrardb-test.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

extern void (*_su_time)(su_time_t* tv);
extern su_time64_t (*_su_nanotime)(su_time64_t*);

namespace flexisip::tester {
namespace {

using namespace std;

void iterateServer(Server& server, const chrono::duration<double> duration) {
	const auto& root = server.getRoot();

	const auto before = chrono::steady_clock::now();
	while (chrono::steady_clock::now() <= before + duration) {
		root->step(1ms);

		this_thread::sleep_for(10ms);
	}
}

/**
 * Test that outgoing transactions destruction is robust to network errors.
 */
int offset = 0;
void resilienceToNetworkError() {

	StaticOverride<void (*)(su_time_t*)> overriddenSuTime{_su_time, [](su_time_t* tv) { tv->tv_sec += offset; }};
	StaticOverride<su_time64_t (*)(su_time64_t*)> overriddenNanoTime{
	    _su_nanotime, [](su_time64_t* t) { return *t = *t + uint64_t(offset) * 1000000000; }};

	auto proxy = Server({
	    {"global/transports", "sip:127.0.0.1:0;transport=udp"},
	    {"module::Registrar/enabled", "true"},
	    {"module::DoSProtection/enabled", "false"},
	    {"module::Registrar/db-implementation", "internal"},
	});
	proxy.start();

	int ackCounter = 0;
	// Create a client that will send (a 100 response to avoid repetitions) a 503 response and then a 200.
	BellesipUtils unstableClient{
	    "127.0.0.1",
	    BELLE_SIP_LISTENING_POINT_RANDOM_PORT,
	    "UDP",
	    [](int) {},
	    [&proxy, &unstableClient, &ackCounter](const belle_sip_request_event_t* event) {
		    if (string(belle_sip_request_get_method(belle_sip_request_event_get_request(event))) == "ACK") {
			    ++ackCounter;
			    return;
		    }

		    belle_sip_response_t* resp;
		    auto* provider = unstableClient.getProvider();
		    resp = belle_sip_response_create_from_request(belle_sip_request_event_get_request(event), 100);
		    belle_sip_provider_send_response(provider, resp);

		    iterateServer(proxy, 0.2s);
		    resp = belle_sip_response_create_from_request(belle_sip_request_event_get_request(event), 503);
		    belle_sip_provider_send_response(provider, resp);

		    iterateServer(proxy, 0.2s);
		    resp = belle_sip_response_create_from_request(belle_sip_request_event_get_request(event), 200);
		    belle_sip_provider_send_response(provider, resp);

		    // Set offset to skip 30 seconds of su_timers (since sofia's timer D cannot be reduced to less than 32s).
		    // https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.2.2
		    offset = 31;
	    },
	    false,
	};

	auto& regDb = proxy.getAgent()->getRegistrarDb();

	constexpr auto& existingContact = "sip:127.0.0.1:7891;transport=udp";
	auto clientPort = to_string(unstableClient.getListeningPort());
	auto unstableClientSip = "sip:127.0.0.1:" + clientPort + ";transport=udp";

	ContactInserter(regDb).setAor("sip:user@localhost"s).setExpire(60s).insert({existingContact});
	ContactInserter(regDb).setAor("sip:unstable-answerer@localhost"s).setExpire(60s).insert({unstableClientSip});
	const auto& records = dynamic_cast<const RegistrarDbInternal&>(regDb.getRegistrarBackend()).getAllRecords();
	BC_HARD_ASSERT_CPP_EQUAL(records.size(), 2);

	string request("INVITE sip:unstable-answerer@127.0.0.1:" + clientPort + R"sip( SIP/2.0
Max-Forwards: 5
To: sip:unstable-answerer@127.0.0.1:7892
From: sip:127.0.0.1:7891;tag=465687829
Call-ID: 1053183492
CSeq: 10 INVITE
Contact: <sip:127.0.0.1:7891;transport=udp>
Content-Length: 0)sip");

	auto msg = make_shared<MsgSip>(0, request);
	auto event = make_shared<RequestSipEvent>(proxy.getAgent(), msg, nullptr);
	auto outgoingTransaction = event->createOutgoingTransaction();
	event->send(msg, nullptr);

	// We want to check that the buffer has not already been freed.
	// Since we use pre-allocated memory, the memory block of the sofia outgoing transaction will not really be
	// freed. su_free will instead fill it with 0xAA.
	// getResponseCode retrieve a "short" from the Sofia struct (orq->orq_status) which means
	// that the value will be 0xAAAA if the buffer has been "freed".

	// 2s wait: first is for sending messages, second to wait the end of the "32s" timer.
	CoreAssert{proxy, unstableClient}
	    .forceIterateThenAssert(0, 2s,
	                            [&outgoingTransaction, &ackCounter] {
		                            FAIL_IF(ackCounter == 0);
		                            FAIL_IF(outgoingTransaction->getResponseCode() == 0xaaaa);
		                            return ASSERTION_PASSED();
	                            })
	    .assert_passed();
}

TestSuite _("OutgoingTransaction",
            {
                CLASSY_TEST(resilienceToNetworkError),
            });
} // namespace
} // namespace flexisip::tester