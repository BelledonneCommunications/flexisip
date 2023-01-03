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

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_parser.h>

#include <bctoolbox/ownership.hh>

#include <flexisip/sip-boolean-expressions.hh>

#include "conditional-routes.hh"
#include "tester.hh"
#include "utils/test-suite.hh"

using namespace flexisip;
using namespace flexisip::tester;
using namespace std;

static msg_t *sipRequest = nullptr;
static msg_t *sipResponse = nullptr;

static const char* raw_request = "REGISTER sip:192.168.0.20 SIP/2.0\r\n"\
							"Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"\
							"From: <sip:jehan-mac@sip.linphone.org>;tag=465687829\r\n"\
							"To: <sip:jehan-mac@sip.linphone.org>\r\n"\
							"Call-ID: 1053183492\r\n"\
							"CSeq: 1 REGISTER\r\n"\
							"Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"\
							"Max-Forwards: 70\r\n"\
							"User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"\
							"Expires: 3600\r\n"\
							"Content-Length: 0\r\n\r\n123456789";

							
static const char * raw_response = "SIP/2.0 180 Ringing\r\n"
			"Via: SIP/2.0/UDP 192.168.1.73:5060;branch=z9hG4bK.hhdJx4~kD;rport\r\n"
			"Record-Route: <sip:91.121.209.194;lr>\r\n"
			"Record-Route: <sip:siproxd@192.168.1.254:5060;lr>\r\n"
			"From: <sip:granny2@sip.linphone.org>;tag=5DuaoDRru\r\n"
			"To: <sip:chmac@sip.linphone.org>;tag=PelIhu0\r\n"
			"Call-ID: e-2Q~fxwNs\r\n"
			"CSeq: 21 INVITE\r\n"
			"user-agent: Linphone/3.6.99 (belle-sip/1.2.4)\r\n"
			"supported: replaces\r\n"
			"supported: outbound\r\n"
			"Content-Length: 0\r\n"
			"\r\n";

static const char* raw_request_2 = "INVITE sip:+331233412341234@sip.example.org;user=phone SIP/2.0\r\n"\
							"Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"\
							"From: <sip:josette@sip.linphone.org>;tag=465687829\r\n"\
							"To: <sip:ghislaine@sip.linphone.org>\r\n"\
							"Call-ID: 1053183492\r\n"\
							"CSeq: 1 INVITE\r\n"\
							"Contact: <sip:josette@192.168.1.8:5062>\r\n"\
							"Max-Forwards: 70\r\n"\
							"User-Agent: Linphone/12.0\r\n"\
							"Content-Length: 0\r\n\r\n123456789";
							
static const char* raw_request_3 = "INVITE sip:+331233412341234@sip.example.org;user=phone SIP/2.0\r\n"\
							"Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"\
							"From: <sip:jean-patrick@sip.linphone.org>;tag=465687829\r\n"\
							"To: <sip:jeanne@sip.linphone.org>\r\n"\
							"Call-ID: 1053183492\r\n"\
							"CSeq: 1 INVITE\r\n"\
							"Contact: <sip:jean-patrick@192.168.1.8:5062>\r\n"\
							"Max-Forwards: 70\r\n"\
							"User-Agent: Linphone/12.0\r\n"\
							"Content-Length: 0\r\n\r\n123456789";

static const char* raw_request_4 = "SUBSCRIBE sip:choupinette@sip.example.org;user=phone SIP/2.0\r\n"\
							"Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"\
							"From: <sip:jean-patrick@sip.linphone.org>;tag=465687829\r\n"\
							"To: <sip:jeanne@sip.linphone.org>\r\n"\
							"Call-ID: 1053183492\r\n"\
							"CSeq: 1 SUBSCRIBE\r\n"\
							"Contact: <sip:jean-patrick@192.168.1.8:5062>\r\n"\
							"Max-Forwards: 70\r\n"\
							"User-Agent: Linphone/12.0\r\n"\
							"Content-Length: 0\r\n\r\n123456789";

static const sip_t & getRequest(){
	return *(sip_t*) msg_object(sipRequest);
}

static auto makeRequest(const char* raw) {
	return ownership::owned(msg_make(sip_default_mclass(), 0, raw, strlen(raw)));
}

static const sip_t & getResponse(){
	return *(sip_t*) msg_object(sipResponse);
}

static void basic_expression(void) {
	shared_ptr<SipBooleanExpression> expr = SipBooleanExpressionBuilder::get().parse("true");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("is_request");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("direction == 'request'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("'toto' == 'titi'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("is_response");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));
	BC_ASSERT_TRUE(expr->eval(getResponse()));
}

static void basic_message_inspection(void){
	shared_ptr<SipBooleanExpression> expr;
	expr = SipBooleanExpressionBuilder::get().parse("from.uri.domain == 'sip.linphone.org'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("from.uri.user == 'jehan-mac'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("from.uri.user contains 'jehan'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.domain contains 'linphone'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.user == 'jehan-claude'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.user != 'jehan-jacques'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));

	// Filter will only be successful if regex match the entire character sequence
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.user regex 'jehan-*'");
	BC_ASSERT_TRUE(expr != nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));

	// Basic regex
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.user regex 'jehan-.*'");
	BC_ASSERT_TRUE(expr != nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));

	// Regex that only work because we now use ECMAScript grammar (do not start with)
	expr = SipBooleanExpressionBuilder::get().parse("from.uri.domain regex '^(?!kijou).*$'");
	BC_ASSERT_TRUE(expr != nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));

	expr = SipBooleanExpressionBuilder::get().parse("request.method == 'REGISTER'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("request.method-name == 'REGISTER'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("defined request.uri.user");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("user-agent contains 'Linphone'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse("is_response && status.code == '180'");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getResponse()));
	
	expr = SipBooleanExpressionBuilder::get().parse("numeric call-id");
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	BC_ASSERT_FALSE(expr->eval(getResponse()));
}

static void complex_expressions(void){
	shared_ptr<SipBooleanExpression> expr;
	
	expr = SipBooleanExpressionBuilder::get().parse(
		"!(defined request.uri.user) && (from.uri.user in 'jehan-mac jehan-michel') && user-agent contains 'Linphone'"
	);
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse(
		"(from.uri.user in 'jehan-kevin jehan-patrick') && user-agent contains 'Linphone'" 
	);
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse(
		"((from.uri.user in 'jehan-kevin jehan-patrick') && user-agent contains 'Linphone' ) || request.method == 'REGISTER'"
	);
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_TRUE(expr->eval(getRequest()));
	
	expr = SipBooleanExpressionBuilder::get().parse(
		"!(from.uri.user in 'jehan-kevin jehan-patrick') && request.method != 'REGISTER'"
	);
	BC_ASSERT_TRUE(expr!=nullptr);
	BC_ASSERT_FALSE(expr->eval(getRequest()));

}

static void invalid_expressions(void){
	shared_ptr<SipBooleanExpression> expr;
	
	try{
		// mising single quotes around constant elements.
		expr = SipBooleanExpressionBuilder::get().parse(
			"!(defined request.uri.user) && (from.uri.user in jehan-mac jehan-michel) && user-agent contains 'Linphone'"
		);
	}catch (...){
	}
	BC_ASSERT_TRUE(expr == nullptr);
	
	try{
		//mising parenthesis
		expr = SipBooleanExpressionBuilder::get().parse(
			"!(defined request.uri.user) && (from.uri.user == 'jehan-mac'"
		);
	}catch (...){
	}
	BC_ASSERT_TRUE(expr == nullptr);
	
}

string serializeRoute(const sip_route_t *route){
	string ret;
	size_t len;
	ret.resize(256);
	len = sip_route_e(&ret[0], ret.size(), (const msg_header_t*)route, 0);
	ret.resize(len);
	return ret;
}

static void route_condition_map(void){
	ConditionalRouteMap routeMap;
	bool loading_ok;
	try{
		routeMap.loadConfig(bcTesterRes("config/routes.conf"));
		loading_ok = true;
	}catch(const exception &e){
		bctbx_error("%s", e.what());
		loading_ok = false;
	}
	BC_ASSERT_TRUE(loading_ok);
	
	const sip_route_t *route;
	string routeStr;

	route = routeMap.resolveRoute(MsgSip(makeRequest(raw_request)));
	BC_ASSERT_PTR_NOT_NULL(route);
	if (route) {
		routeStr = serializeRoute(route);
		BC_ASSERT_STRING_EQUAL(routeStr.c_str(), "<sip:sip1.example.org;transport=tls;lr>");
	}

	route = routeMap.resolveRoute(MsgSip(makeRequest(raw_request_2)));
	BC_ASSERT_PTR_NOT_NULL(route);
	if (route) {
		routeStr = serializeRoute(route);
		BC_ASSERT_STRING_EQUAL(routeStr.c_str(), "<sips:sip2.example.org;lr>");
	}

	route = routeMap.resolveRoute(MsgSip(makeRequest(raw_request_3)));
	BC_ASSERT_PTR_NOT_NULL(route);
	if (route) {
		routeStr = serializeRoute(route);
		BC_ASSERT_STRING_EQUAL(routeStr.c_str(), "<sips:sip3.example.org;lr>");
	}
	route = routeMap.resolveRoute(MsgSip(makeRequest(raw_request_4)));
	BC_ASSERT_PTR_NOT_NULL(route);
	if (route) {
		routeStr = serializeRoute(route);
		BC_ASSERT_STRING_EQUAL(routeStr.c_str(), "<sip:example.org;transport=tcp;lr>");
	}
}

namespace {
TestSuite _("Boolean expressions",
            {TEST_NO_TAG("Basic expression", basic_expression),
             TEST_NO_TAG("Basic message inspection", basic_message_inspection),
             TEST_NO_TAG("More complex expressions", complex_expressions),
             TEST_NO_TAG("Invalid expressions", invalid_expressions),
             TEST_NO_TAG("Route-condition map", route_condition_map)},
            Hooks()
                .beforeSuite([] {
	                sipRequest = msg_make(sip_default_mclass(), 0, raw_request, strlen(raw_request));
	                sipResponse = msg_make(sip_default_mclass(), 0, raw_response, strlen(raw_response));
	                return 0;
                })
                .afterSuite([] {
	                msg_unref(sipRequest);
	                msg_unref(sipResponse);
	                sipRequest = nullptr;
	                sipResponse = nullptr;
	                return 0;
                }));
}
