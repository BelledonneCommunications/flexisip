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

#include "nat/nat-traversal-strategy.hh"

#include <memory>

#include "flexisip/logmanager.hh"

#include "utils/test-suite.hh"

using namespace std;
using namespace sofiasip;

namespace flexisip::tester {

namespace helper {

static shared_ptr<MsgSip> createMsgSip() {
	const auto ms = make_shared<MsgSip>();
	auto* sip = ms->getSip();
	sip->sip_via = static_cast<sip_via_t*>(su_alloc(ms->getHome(), sizeof(sip_via_t)));
	sip->sip_path = static_cast<sip_path_t*>(su_alloc(ms->getHome(), sizeof(sip_path_t)));

	sip->sip_via->v_host = "x.x.x.x";
	sip->sip_via->v_port = "xxxx";
	sip->sip_via->v_protocol = "SIP/2.0/TCP";
	sip->sip_via->v_received = "y.y.y.y";
	sip->sip_via->v_rport = "yyyy";
	sip->sip_path->r_url[0] = {{},        url_sip, '\0',    "sip",           nullptr, nullptr,
	                           "z.z.z.z", "zzzz",  nullptr, "transport=zzz", nullptr, nullptr};

	return ms;
}

static url_t* createSipUrl(su_home_t* home, const bool s = false) {
	auto* url = static_cast<url_t*>(su_alloc(home, sizeof(url_t)));
	url->url_type = (s) ? url_sips : url_sip;
	url->url_scheme = (s) ? "sips" : "sip";
	url->url_host = "x.x.x.x";
	url->url_port = "xxxx";
	return url;
}

} // namespace helper

namespace {

void emptyWithNullptr() {
	BC_ASSERT(NatTraversalStrategy::Helper::empty(nullptr) == true);
}

void emptyWithNullTerminator() {
	BC_ASSERT(NatTraversalStrategy::Helper::empty("\0") == true);
}

void emptyWithNonEmptyData() {
	BC_ASSERT(NatTraversalStrategy::Helper::empty("not_empty") == false);
}

void fixTransportSipUdp() {
	Home home;
	auto* url = helper::createSipUrl(home.home());

	{
		url->url_params = "transport=xxx";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "UDP");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}

	{
		url->url_params = "";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "UDP");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}
}

void fixTransportSipTcp() {
	Home home;
	auto* url = helper::createSipUrl(home.home());

	{
		url->url_params = "transport=xxx";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TCP");

		char parameter[64];
		url_param(url->url_params, "transport", parameter, 64);
		BC_ASSERT_STRING_EQUAL(parameter, "tcp");
	}

	{
		url->url_params = "";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TCP");

		char parameter[64];
		url_param(url->url_params, "transport", parameter, 64);
		BC_ASSERT_STRING_EQUAL(parameter, "tcp");
	}
}

void fixTransportSipTls() {
	Home home;
	auto* url = helper::createSipUrl(home.home());

	{
		url->url_params = "transport=xxx";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TLS");

		char parameter[64];
		url_param(url->url_params, "transport", parameter, 64);
		BC_ASSERT_STRING_EQUAL(parameter, "tls");
	}

	{
		url->url_params = "";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TLS");

		char parameter[64];
		url_param(url->url_params, "transport", parameter, 64);
		BC_ASSERT_STRING_EQUAL(parameter, "tls");
	}
}

void fixTransportSips() {
	Home home;
	auto* url = helper::createSipUrl(home.home(), true);

	{
		url->url_params = "transport=xxx";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TCP");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}

	{
		url->url_params = "";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TCP");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}

	{
		url->url_params = "transport=xxx";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TLS");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}

	{
		url->url_params = "";

		NatTraversalStrategy::Helper::fixTransport(home.home(), url, "TLS");

		BC_ASSERT(url_has_param(url, "transport") == false);
	}
}

void fixPathReceivedAndRport() {
	const auto& ms = helper::createMsgSip();
	auto* sip = ms->getSip();

	NatTraversalStrategy::Helper::fixPath(ms);

	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_host, "y.y.y.y");
	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_port, "yyyy");

	char parameter[64];
	url_param(sip->sip_path->r_url[0].url_params, "transport", parameter, 64);
	BC_ASSERT_STRING_EQUAL(parameter, "tcp");
}

void fixPathReceived() {
	const auto& ms = helper::createMsgSip();
	const auto* sip = ms->getSip();
	sip->sip_via->v_rport = nullptr;

	NatTraversalStrategy::Helper::fixPath(ms);

	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_host, "y.y.y.y");
	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_port, "xxxx");

	char parameter[64];
	url_param(sip->sip_path->r_url[0].url_params, "transport", parameter, 64);
	BC_ASSERT_STRING_EQUAL(parameter, "tcp");
}

void fixPathRport() {
	const auto& ms = helper::createMsgSip();
	const auto* sip = ms->getSip();
	sip->sip_via->v_received = nullptr;

	NatTraversalStrategy::Helper::fixPath(ms);

	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_host, "x.x.x.x");
	BC_ASSERT_STRING_EQUAL(sip->sip_path->r_url[0].url_port, "yyyy");

	char parameter[64];
	url_param(sip->sip_path->r_url[0].url_params, "transport", parameter, 64);
	BC_ASSERT_STRING_EQUAL(parameter, "tcp");
}

TestSuite _("NatTraversalStrategy::Helper",
            {
                TEST_NO_TAG_AUTO_NAMED(emptyWithNullptr),
                TEST_NO_TAG_AUTO_NAMED(emptyWithNullTerminator),
                TEST_NO_TAG_AUTO_NAMED(emptyWithNonEmptyData),
                TEST_NO_TAG_AUTO_NAMED(fixTransportSipUdp),
                TEST_NO_TAG_AUTO_NAMED(fixTransportSipTcp),
                TEST_NO_TAG_AUTO_NAMED(fixTransportSipTls),
                TEST_NO_TAG_AUTO_NAMED(fixTransportSips),
                TEST_NO_TAG_AUTO_NAMED(fixPathReceivedAndRport),
                TEST_NO_TAG_AUTO_NAMED(fixPathReceived),
                TEST_NO_TAG_AUTO_NAMED(fixPathRport),
            });

}

} // namespace flexisip::tester