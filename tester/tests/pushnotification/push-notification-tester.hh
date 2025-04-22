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

#pragma once

#include <chrono>

#include "pushnotification/client.hh"
#include "pushnotification/generic/generic-http2-client.hh"
#include "utils/pns-mock.hh"

using namespace std::chrono_literals;

namespace flexisip::pushnotification::pn_tester {

enum ExpectedResult {
	Success,
	Timeout,
};

/**
 * Common method to run a push test
 */
static void startPushTest(std::shared_ptr<sofiasip::SuRoot> root,
                          Client& client,
                          const std::shared_ptr<Request>& request,
                          const std::string& reqBodyPattern,
                          int responseCode,
                          const std::string& responseBody,
                          Request::State expectedFinalState,
                          bool timeout) {
	std::promise<bool> barrier{};
	std::future<bool> barrier_future = barrier.get_future();
	PnsMock pnsMock;

	// Start of the push notification mock server
	auto isReqPatternMatched =
	    std::async(std::launch::async, [&pnsMock, responseCode, &responseBody, &reqBodyPattern, &barrier, timeout]() {
		    return pnsMock.exposeMock(responseCode, responseBody, reqBodyPattern, std::move(barrier), timeout);
	    });

	// Wait for the server to start
	barrier_future.wait();
	if (!barrier_future.get()) {
		BC_FAIL("Http2 mock server didn't start correctly");
	}

	if (timeout) client.setRequestTimeout(2s);
	// Send the push notification and wait until the request state is "Successful" or "Failed"
	client.sendPush(request);
	sofiasip::Timer timer{root, 50ms};
	auto beforePlus2 = std::chrono::system_clock::now() + 2s;
	timer.setForEver([&request, &beforePlus2, &timeout, &root]() {
		if (request->getState() == Request::State::Successful || request->getState() == Request::State::Failed) {
			su_root_break(root->getCPtr());
		} else if (beforePlus2 < std::chrono::system_clock::now() && !timeout) {
			SLOGW << "Test without timeout did not update request state";
			su_root_break(root->getCPtr());
		}
	});
	su_root_run(root->getCPtr());

	// NgHttp2 server normally don't stop until all connections are closed
	pnsMock.forceCloseServer();

	// Client (Firebase or Apple) onResponse/onError is called and response status is well managed
	BC_ASSERT_TRUE(request->getState() == expectedFinalState);

	// Mock server received a body matching reqBodyPattern, checked only if it's not a timeout case
	if (!timeout) {
		BC_ASSERT_TRUE(isReqPatternMatched.get() == true);
	}
}

/**
 * Common method to run a test for the generic pusher
 */
template <const ExpectedResult expectedResult>
void startGenericPushTest(const std::shared_ptr<sofiasip::SuRoot>& root,
                          PushType pType,
                          const std::shared_ptr<PushInfo>& pushInfo,
                          const std::string& reqBodyPattern,
                          int responseCode,
                          const std::string& responseBody,
                          GenericHttp2Client& genericHttp2Client) {
	genericHttp2Client.enableInsecureTestMode();

	auto request = genericHttp2Client.makeRequest(pType, pushInfo);

	if (expectedResult == Success) {
		startPushTest(root, genericHttp2Client, request, reqBodyPattern, responseCode, responseBody,
		              Request::State::Successful, false);
	} else {
		startPushTest(root, genericHttp2Client, request, reqBodyPattern, responseCode, responseBody,
		              Request::State::Failed, true);
	}
}

} // namespace flexisip::pushnotification::pn_tester