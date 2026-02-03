/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/utils/sip-uri.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

namespace flexisip::tester {

void parsingError() {

	// Valid uri
	sofiasip::Url url{"sip:user@sip.example.org"};
	auto parsingError = SipUri::hasParsingError(url);
	BC_ASSERT_FALSE(parsingError.has_value());

	// Scheme
	url = sofiasip::Url(":user@sip.example.org");
	std::string errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "no scheme found");

	url = sofiasip::Url("sip");
	errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "no scheme found");

	url = sofiasip::Url("soap:user@sip.example.org");
	errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "invalid scheme (soap)");

	// Host
	url = sofiasip::Url("sip:us@er@sip.example.org");
	errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "forbidden '@' character found in host part");

	url = sofiasip::Url("sip:user@sip.ex\\ample.org");
	errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "forbidden '\\' character found in host part");

	// User
	url = sofiasip::Url("sip:us\\er@sip.example.org");
	errorMessage = SipUri::hasParsingError(url).value_or("");
	BC_ASSERT_CPP_EQUAL(errorMessage, "forbidden '\\' character found in user part");

	// Other reserved characters not filtered out
	std::vector<std::string> reserved{";", "/", "?", ":", "&", "=", "+", "$", ","};
	for (const std::string& reserved_char : reserved) {
		url = sofiasip::Url("sip:us" + reserved_char + "er@sip.example.org");
		parsingError = SipUri::hasParsingError(url);
		BC_ASSERT_FALSE(parsingError.has_value());
	}
}

void rfc3261Compare() {
	/* https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.4
	 *
	 * Not testing identity (a == a), as that is trivially true;
	 */

	{
		auto alice1 = SipUri("sip:%61lice@atlanta.com;transport=TCP");
		auto alice2 = SipUri("sip:alice@AtLanTa.CoM;Transport=tcp");
		BC_ASSERT_TRUE(alice1.rfc3261Compare(alice2));
		BC_ASSERT_TRUE(alice2.rfc3261Compare(alice1));
	}

	{
		auto carol1 = SipUri("sip:carol@chicago.com");
		auto carol2 = SipUri("sip:carol@chicago.com;newparam=5");
		auto carol3 = SipUri("sip:carol@chicago.com;security=on");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol3));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol3));
		BC_ASSERT_TRUE(carol3.rfc3261Compare(carol1));
		BC_ASSERT_TRUE(carol3.rfc3261Compare(carol2));
	}

	{
		auto bob1 = SipUri("sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com");
		auto bob2 = SipUri("sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com");
		BC_ASSERT_TRUE(bob1.rfc3261Compare(bob2));
		BC_ASSERT_TRUE(bob2.rfc3261Compare(bob1));
	}

	{
		auto alice1 = SipUri("sip:alice@atlanta.com?subject=project%20x&priority=urgent");
		auto alice2 = SipUri("sip:alice@atlanta.com?priority=urgent&subject=project%20x");
		BC_ASSERT_TRUE(alice1.rfc3261Compare(alice2));
		BC_ASSERT_TRUE(alice2.rfc3261Compare(alice1));
	}

	{ // "different usernames"
		auto alice1 = SipUri("SIP:ALICE@AtLanTa.CoM;Transport=udp");
		auto alice2 = SipUri("sip:alice@AtLanTa.CoM;Transport=UDP");
		BC_ASSERT_FALSE(alice1.rfc3261Compare(alice2));
		BC_ASSERT_FALSE(alice2.rfc3261Compare(alice1));
	}

	{ // "can resolve to different ports"
		auto bob1 = SipUri("sip:bob@biloxi.com");
		auto bob2 = SipUri("sip:bob@biloxi.com:5060");
		BC_ASSERT_FALSE(bob1.rfc3261Compare(bob2));
		BC_ASSERT_FALSE(bob2.rfc3261Compare(bob1));
	}

	{ // "can resolve to different transports"
		auto bob1 = SipUri("sip:bob@biloxi.com");
		auto bob2 = SipUri("sip:bob@biloxi.com:6000;transport=udp");
		BC_ASSERT_FALSE(bob1.rfc3261Compare(bob2));
		BC_ASSERT_FALSE(bob2.rfc3261Compare(bob1));
	}

	{ // "can resolve to different port and transports"
		auto bob1 = SipUri("sip:bob@biloxi.com");
		auto bob2 = SipUri("sip:bob@biloxi.com:6000;transport=tcp");
		BC_ASSERT_FALSE(bob1.rfc3261Compare(bob2));
		BC_ASSERT_FALSE(bob2.rfc3261Compare(bob1));
	}

	{ // "different header component"
		auto carol1 = SipUri("sip:carol@chicago.com");
		auto carol2 = SipUri("sip:carol@chicago.com?Subject=next%20meeting");
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol1));
	}

	{ // "even though that's what sip:bob@192.0.2.4 phone21.boxesbybob.com resolves to"
		auto bob1 = SipUri("sip:bob@phone21.boxesbybob.com");
		auto bob2 = SipUri("sip:bob@192.0.2.4");
		BC_ASSERT_FALSE(bob1.rfc3261Compare(bob2));
		BC_ASSERT_FALSE(bob2.rfc3261Compare(bob1));
	}

	/* "Note that equality is not transitive"
	   "Any uri-parameter appearing in both URIs must match." but
	   "All other uri-parameters [(except user, ttl, method, and maddr)] appearing in only one URI are ignored when
	   comparing the URIs"
	 */
	{
		auto carol1 = SipUri("sip:carol@chicago.com");
		auto carol2 = SipUri("sip:carol@chicago.com;security=on");
		auto carol3 = SipUri("sip:carol@chicago.com;security=off");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol3));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol3));
		BC_ASSERT_TRUE(carol3.rfc3261Compare(carol1));
		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol2));
	}

	// Extra tests

	{ // Param value is case-insensitive
		auto carol1 = SipUri("sip:carol@chicago.com;transport=TCP");
		auto carol2 = SipUri("sip:carol@chicago.com;transport=tcp");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
	}

	{ // Param name is case-insensitive
		auto carol1 = SipUri("sip:carol@chicago.com;Transport=udp");
		auto carol2 = SipUri("sip:carol@chicago.com;transport=tcp");
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol1));
	}

	{ // Value-less parameter
		auto carol1 = SipUri("sip:carol@chicago.com;transport=tcp;lr;ttl=20");
		auto carol2 = SipUri("sip:carol@chicago.com;transport=tcp;lr=9;ttl=20");
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol1));
	}

	{ // Special-cased params
		auto carol1 = SipUri("sip:carol@chicago.com");
		auto carol2 = SipUri("sip:carol@chicago.com;user=phone");
		auto carol3 = SipUri("sip:carol@chicago.com;ttl=30");
		auto carol4 = SipUri("sip:carol@chicago.com;method=REGISTER");
		auto carol5 = SipUri("sip:carol@chicago.com;maddr=224.2.0.1");

		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol1));

		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol3));
		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol1));

		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol4));
		BC_ASSERT_FALSE(carol4.rfc3261Compare(carol1));

		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol5));
		BC_ASSERT_FALSE(carol5.rfc3261Compare(carol1));
	}

	// Headers

	{ // Call-ID
		auto carol1 = SipUri("sip:carol@chicago.com");
		auto carol2 = SipUri("sip:carol@chicago.com?Call-id=deadbeef");
		auto carol3 = SipUri("sip:carol@chicago.com?i=deadbeef");
		auto carol4 = SipUri("sip:carol@chicago.com?i=deAdbEef");

		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol3));
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol4));

		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol1));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol3));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol4));

		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol1));
		BC_ASSERT_TRUE(carol3.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol4));

		BC_ASSERT_FALSE(carol4.rfc3261Compare(carol1));
		BC_ASSERT_FALSE(carol4.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol4.rfc3261Compare(carol3));
	}

	{ // Aliases
		auto carol1 = SipUri("sip:carol@chicago.com?content-Encoding=gzip&cOntent-length=349&content-tYpe=application/"
		                     "sdp&subJect=Weekend plans&supPorted=100rel");
		auto carol2 = SipUri("sip:carol@chicago.com?l=349&k=100Rel&s=weekenD plans&c=Application/SDP&e=gZip");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
	}

	{ // Quoted strings
		auto carol1 = SipUri(R"(sip:carol@chicago.com?Warning=370 devnull "Choose a bigger pipe")");
		auto carol2 = SipUri(R"(sip:carol@chicago.com?Warning=370 DEVNULL "Choose a bigger pipe")");
		auto carol3 = SipUri(R"(sip:carol@chicago.com?Warning=370 DEVNULL "CHOOSE A BIGGER PIPE")");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_FALSE(carol1.rfc3261Compare(carol3));

		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
		BC_ASSERT_FALSE(carol2.rfc3261Compare(carol3));

		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol1));
		BC_ASSERT_FALSE(carol3.rfc3261Compare(carol2));
	}

	{ // Embedded URIs
		auto carol1 = SipUri("sip:carol@chicago.com?m=sip:carol@chicago.com&from=sip:biloxi.com;transport=tcp;method="
		                     "REGISTER&To=sip:%61lice@atlanta.com");
		auto carol2 = SipUri("sip:carol@chicago.com?Contact=sip:carol@chicago.com;security=on&f=sip:biloxi.com;method="
		                     "REGISTER;transport=tcp&t=sip:alice@AtLanTa.CoM");
		BC_ASSERT_TRUE(carol1.rfc3261Compare(carol2));
		BC_ASSERT_TRUE(carol2.rfc3261Compare(carol1));
	}
}

void fromName() {
	const auto* canon = "sip.example.org";
	const auto* host = "127.0.0.1";
	const auto* port = "5060";

	{
		const tp_name_t name{.tpn_proto = "uDp", .tpn_canon = canon, .tpn_host = host, .tpn_port = port};
		const auto uri = SipUri::fromName(&name);
		BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), SipUri::Scheme::sip);
		BC_ASSERT_CPP_EQUAL(uri.getHost(), canon);
		BC_ASSERT_CPP_EQUAL(uri.getPort(), port);
		BC_ASSERT(uri.getParam("transport").empty());
	}
	{
		const tp_name_t name{.tpn_proto = "udP", .tpn_canon = nullptr, .tpn_host = host, .tpn_port = port};
		const auto uri = SipUri::fromName(&name);
		BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), SipUri::Scheme::sip);
		BC_ASSERT_CPP_EQUAL(uri.getHost(), host);
		BC_ASSERT_CPP_EQUAL(uri.getPort(), port);
		BC_ASSERT(uri.getParam("transport").empty());
	}
	{
		const tp_name_t name{.tpn_proto = "tcP", .tpn_canon = canon, .tpn_host = host, .tpn_port = port};
		const auto uri = SipUri::fromName(&name);
		BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), SipUri::Scheme::sip);
		BC_ASSERT_CPP_EQUAL(uri.getHost(), canon);
		BC_ASSERT_CPP_EQUAL(uri.getPort(), port);
		BC_ASSERT_CPP_EQUAL(uri.getParam("transport"), "tcp");
	}
	{
		const tp_name_t name{.tpn_proto = "Tls", .tpn_canon = canon, .tpn_host = host, .tpn_port = port};
		const auto uri = SipUri::fromName(&name);
		BC_ASSERT_ENUM_EQUAL(uri.getSchemeType(), SipUri::Scheme::sips);
		BC_ASSERT_CPP_EQUAL(uri.getHost(), canon);
		BC_ASSERT_CPP_EQUAL(uri.getPort(), port);
		BC_ASSERT(uri.getParam("transport").empty());
	}
}

namespace {

TestSuite _{
    "SipUri",
    {
        CLASSY_TEST(parsingError),
        CLASSY_TEST(rfc3261Compare),
        CLASSY_TEST(fromName),
    },
};
}
} // namespace flexisip::tester