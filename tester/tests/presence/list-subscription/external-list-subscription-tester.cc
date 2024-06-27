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

#include <belle-sip/belle-sip.h>

#include "presence/subscription/external-list-subscription.hh"

#include "utils/bellesip-utils.hh"
#include "utils/core-assert.hh"
#include "utils/string-formatter.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"
#include "utils/thread/auto-thread-pool.hh"
#include "utils/tmp-dir.hh"

using namespace std;
using namespace soci;
using namespace chrono;

namespace flexisip::tester {
namespace {

struct BelleSipStringDeleter {
	constexpr BelleSipStringDeleter() noexcept = default;
	void operator()(char* ptr) const noexcept {
		belle_sip_free(ptr);
	}
};

using BelleSipString = unique_ptr<char, BelleSipStringDeleter>;

/*
 * Test that new listeners are appended to the back of the list when the SQL request successfully returns a list of
 * parsable entries.
 */
void getUsersListAppendsListenersToTheBack() {
	const auto expectedDisplayName = "User 1"sv;
	const auto expectedSipIdentity = "sip:user-1@localhost"sv;

	// Initialize test tools.
	BellesipUtils utils{"127.0.0.1", 0, "tcp", [](int) {}, [](const belle_sip_request_event_t*) {}};
	CoreAssert asserter{utils};
	AutoThreadPool threadPool{2, 0};
	connection_pool connectionPool{1};
	connectionPool.at(0).open("sqlite3", ":memory:");

	// Initialize stub database.
	auto& session = connectionPool.at(0);
	session << R"sql(CREATE TABLE Users (Address TEXT, FromIdentity TEXT, ToIdentity TEXT))sql";
	StringFormatter formatter{R"(INSERT INTO Users VALUES ("{displayName} <{sipId}>", "{sipId}", "{sipId}"))"};
	session << formatter.format({{"displayName", expectedDisplayName.data()}, {"sipId", expectedSipIdentity.data()}});
	session << formatter.format({{"displayName", expectedDisplayName.data()}, {"sipId", expectedSipIdentity.data()}});
	session << formatter.format({{"displayName", "User 2"}, {"sipId", "sip:user-2@localhost"}});

	// Generate stub request and transaction in order to create an ExternalListSubscription.
	ostringstream rawRequest{};
	rawRequest << "REGISTER sip:localhost SIP/2.0\r\n"
	           << "Via: SIP/2.0/TCP 127.0.0.1:1234;branch=" BELLE_SIP_BRANCH_MAGIC_COOKIE ".stub-branch\r\n"
	           << "Max-Forwards: 70\r\n"
	           << "From: \"" << expectedDisplayName << "\" <" << expectedSipIdentity << ">;tag=stub-from-tag\r\n"
	           << "To: \"" << expectedDisplayName << "\" <" << expectedSipIdentity << ">\r\n"
	           << "Contact: <" << expectedSipIdentity << ">\r\n"
	           << "Call-ID: stub-call-id\r\n"
	           << "CSeq: 20 REGISTER\r\n"
	           << "Expires: 3600\r\n"
	           << "Content-Length: 0\r\n\r\n";
	auto* request = BELLE_SIP_REQUEST(belle_sip_message_parse(rawRequest.str().c_str()));
	auto* transaction = belle_sip_provider_create_server_transaction(utils.getProvider(), request);
	auto statsCounter = make_unique<StatCounter64>("stub-name", "stub-help", 0xdead);
	auto stats = make_shared<StatPair>(statsCounter.get(), statsCounter.get());

	auto externalListSubscription = make_shared<ExternalListSubscription>(
	    0xdead, transaction, utils.getProvider(), 0xdead, stats, [](const auto&) {},
	    "SELECT * FROM Users WHERE FromIdentity = :from AND ToIdentity = :to", &connectionPool, &threadPool);

	BC_ASSERT(asserter.iterateUpTo(
	    0x20,
	    [&listeners = externalListSubscription->getListeners(), &expectedSipIdentity, &expectedDisplayName]() {
		    if (listeners.size() < 2) {
			    return ASSERTION_FAILED("Listeners list has the wrong size");
		    }
		    FAIL_IF(listeners.size() != 2);
		    for (const auto& listener : listeners) {
			    const auto displayName = listener->getName();
			    const auto sipId = BelleSipString{belle_sip_uri_to_string(listener->getPresentityUri())};
			    FAIL_IF(displayName != expectedDisplayName);
			    FAIL_IF(sipId.get() != expectedSipIdentity);
		    }
		    return ASSERTION_PASSED();
	    },
	    2s));

	belle_sip_transaction_terminate(reinterpret_cast<belle_sip_transaction*>(transaction));
}

const TestSuite _("ExternalListSubscription",
                  {
                      CLASSY_TEST(getUsersListAppendsListenersToTheBack),
                  });

} // namespace
} // namespace flexisip::tester