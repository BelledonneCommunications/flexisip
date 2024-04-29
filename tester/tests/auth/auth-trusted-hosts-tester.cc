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

#include <string>

#include "auth-utils.hh"
#include "sofia-wrapper/nta-agent.hh"
#include "utils/server/proxy-server.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std::string_literals;
using namespace sofiasip;
using namespace flexisip;
using namespace flexisip::tester;
using namespace flexisip::tester::authentication;

namespace {
const auto contact = "toto@example.org";
const auto sipUri = "sip:"s + contact;

// Trusted-hosts list is empty, all requests are rejected
void rejectUnauthRequest() {
	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::AuthTrustedHosts/enabled", "true"},
	              {"module::Authorization/enabled", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:localhost:0");

	const auto request = registerRequest(sipUri, "1");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());

	// expect 500 internal error because no authentication challenger module is present
	BC_ASSERT_CPP_EQUAL(transaction->getStatus(), 500);
}

// Add localhost to trusted-host
void acceptTrustedHost() {
	Server proxy({{"module::Registrar/reg-domains", "*"},
	              {"module::AuthTrustedHosts/enabled", "true"},
	              {"module::AuthTrustedHosts/trusted-hosts", "localhost"},
	              {"module::Authorization/enabled", "true"}});

	const auto& root = proxy.getRoot();
	proxy.start();
	NtaAgent UAClient(root, "sip:localhost:0");

	const auto request = registerRequest(sipUri, "1");
	const auto transaction = sendRequest(UAClient, root, request, proxy.getFirstPort());
	checkResponse(transaction, response_200_ok);
}

TestSuite _("AuthTrustedHosts",
            {
                CLASSY_TEST(rejectUnauthRequest),
                CLASSY_TEST(acceptTrustedHost),
            });
} // namespace