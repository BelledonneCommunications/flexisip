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

#include "utils/configuration/transport.hh"

#include "exceptions/bad-configuration.hh"
#include "flexisip/configmanager.hh"
#include "linphone++/core.hh"
#include "linphone++/factory.hh"
#include "linphone/misc.h"
#include "utils/client-core.hh"
#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip::tester {

namespace {

void configureTransportWithSipScheme() {
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sip:sip.example.org:5060", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sip:sip.example.org:5060;transport=udp", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sip:sip.example.org:5060;transport=tcp", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sip:sip.example.org:5060;transport=tls", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
}

void configureTransportWithSipsScheme() {
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sips:sip.example.org:5060;transport=udp", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), 5060);
	}
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sips:sip.example.org:5060", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
	{
		const auto transports = linphone::Factory::get()->createTransports();
		const ConfigString parameter{"transport", "", "sips:sip.example.org:5060;transport=tcp", 0};

		configuration_utils::configureTransport(transports, &parameter);

		BC_ASSERT_CPP_EQUAL(transports->getUdpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTcpPort(), LC_SIP_TRANSPORT_DONTBIND);
		BC_ASSERT_CPP_EQUAL(transports->getTlsPort(), 5060);
		BC_ASSERT_CPP_EQUAL(transports->getDtlsPort(), LC_SIP_TRANSPORT_DONTBIND);
	}
}

void configureTransportWithMissingPortInUri() {
	const auto transports = linphone::Factory::get()->createTransports();
	const ConfigString parameter{"transport", "", "sip:missing-port-in-uri@sip.example.org;transport=tcp", 0};

	BC_ASSERT_THROWN(configuration_utils::configureTransport(transports, &parameter), BadConfiguration)
}

void configureTransportWithInvalidSipUri() {
	const auto transports = linphone::Factory::get()->createTransports();

	static const vector<string> invalidSipUris{
	    "invalid:sip.example.org:5060;transport=tcp", // invalid scheme
	    "sip:userinfo@inv@lid:5060;transport=tcp",    // invalid host
	};

	for (const auto& invalidSipUri : invalidSipUris) {
		const ConfigString parameter{"transport", "", invalidSipUri, 0};
		BC_ASSERT_THROWN(configuration_utils::configureTransport(transports, &parameter), BadConfiguration)
	}
}

void configureTransportWithForbiddenTransportUriParameter() {
	const auto transports = linphone::Factory::get()->createTransports();
	const ConfigString parameter{"transport", "", "sip:sip.example.org;transport=forbidden", 0};

	BC_ASSERT_THROWN(configuration_utils::configureTransport(transports, &parameter), BadConfiguration)
}

void configureTransportWithForbiddenUriScheme() {
	const auto transports = linphone::Factory::get()->createTransports();
	const ConfigString parameter{"transport", "", "sips:sip.example.org;transport=tcp", 0};

	BC_ASSERT_THROWN(configuration_utils::configureTransport(transports, &parameter, {}, {}), BadConfiguration)
}

void parseInternetAddress() {
	{
		const auto [ipAddress, ipFamily] = configuration_utils::parseInternetAddress("127.0.0.1");
		BC_ASSERT_CPP_EQUAL(ipAddress, "127.0.0.1");
		BC_ASSERT_CPP_EQUAL(ipFamily, AF_INET);
	}
	{
		const auto [ipAddress, ipFamily] = configuration_utils::parseInternetAddress("::1");
		BC_ASSERT_CPP_EQUAL(ipAddress, "::1");
		BC_ASSERT_CPP_EQUAL(ipFamily, AF_INET6);
	}
}

void parseInternetAddressWithUnknownNameOrService() {
	const auto [ipAddress, ipFamily] = configuration_utils::parseInternetAddress("test.example");
	BC_ASSERT_CPP_EQUAL(ipAddress, "");
	BC_ASSERT_CPP_EQUAL(ipFamily, AF_UNSPEC);
}

void configureNatAddresses() {
	const auto core = tester::minimalCore();
	{
		const auto policy = core->createNatPolicy();
		const ConfigStringList parameter{"nat-addresses", "", "", 0};

		configuration_utils::configureNatAddresses(policy, &parameter);

		BC_ASSERT_CPP_EQUAL(policy->getNatV4Address(), "");
		BC_ASSERT_CPP_EQUAL(policy->getNatV6Address(), "");
	}
	{
		const auto policy = core->createNatPolicy();
		const ConfigStringList parameter{"nat-addresses", "", "127.0.0.1", 0};

		configuration_utils::configureNatAddresses(policy, &parameter);

		BC_ASSERT_CPP_EQUAL(policy->getNatV4Address(), "127.0.0.1");
		BC_ASSERT_CPP_EQUAL(policy->getNatV6Address(), "");
	}
	{
		const auto policy = core->createNatPolicy();
		const ConfigStringList parameter{"nat-addresses", "", "::1 127.0.0.1", 0};

		configuration_utils::configureNatAddresses(policy, &parameter);

		BC_ASSERT_CPP_EQUAL(policy->getNatV4Address(), "127.0.0.1");
		BC_ASSERT_CPP_EQUAL(policy->getNatV6Address(), "::1");
	}
}

void configureNatAddressesWithUnknownNameOrService() {
	const auto core = tester::minimalCore();

	const auto policy = core->createNatPolicy();
	const ConfigStringList parameter{"nat-addresses", "", "::1 test.example", 0};

	BC_ASSERT_THROWN(configuration_utils::configureNatAddresses(policy, &parameter), BadConfiguration)
}

void configureNatAddressesWithSeveralIPv4Addresses() {
	const auto core = tester::minimalCore();

	const auto policy = core->createNatPolicy();
	const ConfigStringList parameter{"nat-addresses", "", "127.0.0.1 127.0.0.2", 0};

	BC_ASSERT_THROWN(configuration_utils::configureNatAddresses(policy, &parameter), BadConfiguration)
}

void configureNatAddressesWithSeveralIPv6Addresses() {
	const auto core = tester::minimalCore();

	const auto policy = core->createNatPolicy();
	const ConfigStringList parameter{"nat-addresses", "", "::1 ::2", 0};

	BC_ASSERT_THROWN(configuration_utils::configureNatAddresses(policy, &parameter), BadConfiguration)
}

TestSuite _{
    "utils::configuration::transport",
    {
        CLASSY_TEST(configureTransportWithSipScheme),
        CLASSY_TEST(configureTransportWithSipsScheme),
        CLASSY_TEST(configureTransportWithInvalidSipUri),
        CLASSY_TEST(configureTransportWithMissingPortInUri),
        CLASSY_TEST(configureTransportWithForbiddenTransportUriParameter),
        CLASSY_TEST(configureTransportWithForbiddenUriScheme),
        CLASSY_TEST(parseInternetAddress),
        CLASSY_TEST(parseInternetAddressWithUnknownNameOrService),
        CLASSY_TEST(configureNatAddresses),
        CLASSY_TEST(configureNatAddressesWithUnknownNameOrService),
        CLASSY_TEST(configureNatAddressesWithSeveralIPv4Addresses),
        CLASSY_TEST(configureNatAddressesWithSeveralIPv6Addresses),
    },
};

} // namespace
} // namespace flexisip::tester