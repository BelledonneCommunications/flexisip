/*
 * Copyright (C) 2017  Belledonne Communications SARL
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "tester.hh"
#include "flexisip/sip-boolean-expressions.hh"
#include "sofia-sip/sip.h"
#include "sofia-sip/sip_parser.h"

using namespace flexisip;
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

static int beforeSuite(){
	sipRequest = msg_make(sip_default_mclass(), 0, raw_request, strlen(raw_request));
	sipResponse = msg_make(sip_default_mclass(), 0, raw_response, strlen(raw_response));
	return 0;
}

static int afterSuite(){
	msg_unref(sipRequest);
	msg_unref(sipResponse);
	sipRequest = nullptr;
	sipResponse = nullptr;
	return 0;
}

static const sip_t & getRequest(){
	return *(sip_t*) msg_object(sipRequest);
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
	
	expr = SipBooleanExpressionBuilder::get().parse("to.uri.user regexp 'jehan-*'");
	BC_ASSERT_TRUE(expr!=nullptr);
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


static test_t tests[] = {
	TEST_NO_TAG("Basic expression", basic_expression),
	TEST_NO_TAG("Basic message inspection", basic_message_inspection),
	TEST_NO_TAG("More complex expressions", complex_expressions),
	TEST_NO_TAG("Invalid expressions", invalid_expressions)
};

test_suite_t boolean_expressions_suite = {
	"Boolean expressions",
	beforeSuite,
	afterSuite,
	NULL,
	NULL,
	sizeof(tests) / sizeof(tests[0]),
	tests
};
