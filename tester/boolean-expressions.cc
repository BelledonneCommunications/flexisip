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


static msg_t *sipMessage = nullptr;

static const char* raw_message = "REGISTER sip:192.168.0.20 SIP/2.0\r\n"\
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

static int beforeSuite(){
	sipMessage = msg_make(sip_default_mclass(), 0, raw_message, strlen(raw_message));
}

static int afterSuite(){
	msg_unref(sipMessage);
	sipMessage = nullptr;
}

static sip_t *getSip(){
	return (sip_t*) msg_object(sipMessage);
}

static void basic_expression(void) {
	
}

static test_t tests[] = {
	TEST_NO_TAG("Basic expression", basic_expression),
};

test_suite_t grammar_suite = {
	"Boolean expressions",
	beforeSuite,
	afterSuite,
	NULL,
	NULL,
	sizeof(tests) / sizeof(tests[0]),
	tests
};
