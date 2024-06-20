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

#include <csignal>

#include "bctoolbox/tester.h"

#include "flexisip/module-registrar.hh"

#include "registrar/extended-contact.hh"
#include "utils/proxy-server.hh"
#include "utils/temp-file.hh"
#include "utils/test-patterns/test.hh"
#include "utils/successful-bind-listener.hh"
#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;
using namespace chrono_literals;

namespace flexisip::tester::module_registrar {

namespace {

void static_records_file_is_read_on_SIGUSR1() {
	const auto sendSignal = [pid = getpid()] {
		kill(pid, SIGUSR1); // No, this is not suicide
	};
	const auto aor = "sip:contact@domain";
	const auto contact1 = "<sip:127.0.0.1:5460>";
	const auto contact2 = "<sip:192.168.0.1:5160>";
	const auto contact3 = "<sip:192.168.0.2:3125>";
	const TempFile staticRecordsFile{};
	staticRecordsFile.writeStream() << "<" << aor << "> " << contact1 << "," << contact2 << "," << contact3;

	Server proxyServer({
	    {"module::Registrar/static-records-file", staticRecordsFile.getFilename()},
	    // Requesting bind on port 0 to let the kernel find any available port
	    {"global/transports", "sip:127.0.0.1:0"},
	});
	auto& root = *proxyServer.getRoot();
	proxyServer.start();
	auto& regDb = proxyServer.getAgent()->getRegistrarDb();
	const auto listener = std::make_shared<SuccessfulBindListener>();

	sendSignal();
	root.step(1ms);

	{
		regDb.fetch(SipUri(aor), listener);
		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(fetchedContacts.size(), 3, size_t, "%zx");
		const auto& last = **fetchedContacts.latest();
		BC_ASSERT_TRUE(url_cmp_all(last.mSipContact->m_url, sofiasip::Url(contact3).get()));
	}

	// Remove contact3
	staticRecordsFile.writeStream() << "<" << aor << "> " << contact1 << "," << contact2;
	sendSignal();
	root.step(1ms);

	{
		regDb.fetch(SipUri(aor), listener);
		const auto& fetchedContacts = listener->mRecord->getExtendedContacts();
		BC_ASSERT_EQUAL(fetchedContacts.size(), 2, size_t, "%zx");
		const auto& last = **fetchedContacts.latest();
		BC_ASSERT_TRUE(url_cmp_all(last.mSipContact->m_url, sofiasip::Url(contact2).get()));
	}
}

/*
 * Test that module::Registrar/max-contacts-per-registration value must be strictly positive.
 */
void maxContactsPerRegistrationParameter() {
	const pair<string, string> configName{"module::Registrar", "max-contacts-per-registration"};

	{
		Server proxy{{{configName.first + "/" + configName.second, "1"}}};
		proxy.start();
	}
	{
		Server proxy{{{configName.first + "/" + configName.second, "0"}}};
		BC_ASSERT_THROWN(proxy.start(), FlexisipException);
	}
	{
		Server proxy{{{configName.first + "/" + configName.second, "-1"}}};
		BC_ASSERT_THROWN(proxy.start(), FlexisipException);
	}
}

TestSuite _("RegistrarModule",
            {
                CLASSY_TEST(static_records_file_is_read_on_SIGUSR1),
                CLASSY_TEST(maxContactsPerRegistrationParameter),
            });

} // namespace

} // namespace flexisip::tester::module_registrar