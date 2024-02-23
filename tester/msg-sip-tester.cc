/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2022 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "flexisip/logmanager.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"

#include "utils/test-patterns/test.hh"
#include "utils/test-suite.hh"

using namespace std;

namespace flexisip {
namespace tester {

string rawMessage = "MESSAGE sip:francois.grisez@sip.linphone.org SIP/2.0\r\n"
                    "Via: SIP/2.0/TLS [2a01:e0a:278:9f60:7a23:c334:1651:2503]:36676;branch=z9hG4bK.ChN0lTDpQ;rport\r\n"
                    "From: <sip:anthony.gauchy@sip.linphone.org>;tag=iXiKd6FuX\r\n"
                    "To: sip:francois.grisez@sip.linphone.org\r\n"
                    "CSeq: 20 MESSAGE\r\n"
                    "Call-ID: NISmf-QTgo\r\n"
                    "Max-Forwards: 70\r\n"
                    "Supported: replaces, outbound, gruu\r\n"
                    "Date: Wed, 06 Oct 2021 08:43:31 GMT\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 4\r\n"
                    "User-Agent: Linphone Desktop/4.3.0-beta-33-gc3ac9637 (Manjaro Linux, Qt 5.12.5) "
                    "LinphoneCore/5.0.22-1-g8c5243994\r\n"
                    "Proxy-Authorization:  Digest realm=\"sip.linphone.org\", "
                    "nonce=\"1tMH5QAAAABVHBjkAADjdHyvMMkAAAAA\", algorithm=SHA-256, opaque=\"+GNywA==\", "
                    "username=\"anthony.gauchy\",  uri=\"sip:francois.grisez@sip.linphone.org\", "
                    "response=\"787857520cf0cd3f3f451ff7e867aa03536e8a7fed461fe2d14569d928f9296d\", "
                    "cnonce=\"UVZ7dG3P9Kx6j0na\", nc=0000003f, qop=auth\r\n"
                    "\r\n"
                    "1234";

string rawRegister = "REGISTER sip:192.168.0.20 SIP/2.0\r\n"
                     "Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"
                     "From: <sip:jehan-mac@sip.linphone.org>;tag=465687829\r\n"
                     "To: <sip:jehan-mac@sip.linphone.org>\r\n"
                     "Call-ID: 1053183492\r\n"
                     "CSeq: 1 REGISTER\r\n"
                     "Contact: <sip:jehan-mac@192.168.1.8:5062>\r\n"
                     "Max-Forwards: 70\r\n"
                     "User-Agent: Linphone/3.3.99.10 (eXosip2/3.3.0)\r\n"
                     "Expires: 3600\r\n"
                     "Content-Length: 9\r\n\r\n123456789";

static const char* rawSubscribe = "SUBSCRIBE sip:jeanette@sip.example.org;user=phone SIP/2.0\r\n"
                                  "Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"
                                  "From: <sip:jean-patrick@sip.linphone.org>;tag=465687829\r\n"
                                  "To: <sip:jeanne@sip.linphone.org>\r\n"
                                  "Call-ID: 1053183492\r\n"
                                  "CSeq: 1 SUBSCRIBE\r\n"
                                  "Contact: <sip:jean-patrick@192.168.1.8:5062>\r\n"
                                  "Max-Forwards: 70\r\n"
                                  "User-Agent: Linphone/12.0\r\n"
                                  "Content-Length: 9\r\n\r\n123456789";

static const char* rawEmptySubscribe = "SUBSCRIBE sip:jeanette@sip.example.org;user=phone SIP/2.0\r\n"
                                       "Via: SIP/2.0/UDP 192.168.1.8:5062;rport;branch=z9hG4bK1439638806\r\n"
                                       "From: <sip:jean-patrick@sip.linphone.org>;tag=465687829\r\n"
                                       "To: <sip:jeanne@sip.linphone.org>\r\n"
                                       "Call-ID: 1053183492\r\n"
                                       "CSeq: 1 SUBSCRIBE\r\n"
                                       "Contact: <sip:jean-patrick@192.168.1.8:5062>\r\n"
                                       "Max-Forwards: 70\r\n"
                                       "User-Agent: Linphone/12.0\r\n"
                                       "Content-Length: 0";

string rawInvite =
    "INVITE sip:participant1@127.0.0.1:5360 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP "
    "10.23.17.117:22600;branch=z9hG4bK-d8754z-4d7620d2feccbfac-1---d8754z-;rport=4820;received=202.165.193.129\r\n"
    "Max-Forwards: 70\r\n"
    "Contact: <sip:bcheong@202.165.193.129:4820>\r\n"
    "To: <sip:participant1@127.0.0.1>\r\n"
    "From: <sip:anthony@127.0.0.1>;tag=465687829\r\n"
    "Call-ID: Y2NlNzg0ODc0ZGIxODU1MWI5MzhkNDVkNDZhOTQ4YWU.\r\n"
    "CSeq: 1 INVITE\r\n"
    "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK\r\n"
    "Content-Type: application/sdp\r\n"
    "Supported: replaces\r\n"
    "Supported: 100rel\r\n"
    "Authorization: Digest username=\"003332176\", realm=\"sip.ovh.net\", "
    "nonce=\"24212965507cde726e8bc37e04686459\", uri=\"sip:sip.ovh.net\", "
    "response=\"896e786e9c0525ca3085322c7f1bce7b\", algorithm=MD5, opaque=\"241b9fb347752f2\"\r\n"
    "User-Agent: X-Lite 4 release 4.0 stamp 58832\r\n"
    "\r\n"
    // Request body
    "v=0\r\n"
    "o=anthony.gauchy 3102 279 IN IP4 127.0.0.1\r\n"
    "s=Talk\r\n"
    "c=IN IP4 127.0.0.1\r\n"
    "t=0 0\r\n"
    "m=audio 7078 RTP/AVP 111 110 3 0 8 101\r\n"
    "a=rtpmap:111 speex/16000\r\n"
    "a=fmtp:111 vbr=on\r\n"
    "a=rtpmap:110 speex/8000\r\n"
    "a=fmtp:110 vbr=on\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=fmtp:101 0-11\r\n"
    "m=video 8078 RTP/AVP 99 97 98\r\n"
    "c=IN IP4 192.168.0.18\r\n"
    "b=AS:380\r\n"
    "a=rtpmap:99 MP4V-ES/90000\r\n"
    "a=fmtp:99 profile-level-id=3\r\n";

class MsgSipLogTest : public Test {
public:
	void operator()() override {
		MsgSip invite{0, rawInvite};

		/*
		 * CASE : NOT IN SHOW BODY FOR
		 */
		MsgSip::setShowBodyFor("request.method == 'MESSAGE'"s);
		stringstream out;
		out << invite;
		auto invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted != invite.msgAsString());
		BC_ASSERT_TRUE(invitePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(invitePrinted.find("v=0\r\n") == string::npos);
		/*-------------------------------*/

		/*
		 * CASE : ADDED IN SHOW BODY FOR
		 */
		MsgSip::setShowBodyFor("request.method == 'INVITE'"s);
		out.str("");
		out << invite;
		invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted == invite.msgAsString());
		/*-------------------------------*/

		/*
		 * CASE : FALSE SHOW BODY FOR
		 */
		MsgSip::setShowBodyFor("false");
		out.str("");
		out << invite;
		invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted != invite.msgAsString());
		BC_ASSERT_TRUE(invitePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(invitePrinted.find("v=0\r\n") == string::npos);
		/*-------------------------------*/

		/*
		 * CASE : COMPLEX CASE WITH MULTIPLE SIP METHOD
		 */
		MsgSip message{0, rawMessage};
		MsgSip registerSip{0, rawRegister};
		MsgSip subscribe{0, rawSubscribe};
		MsgSip emptySubscribe{0, rawEmptySubscribe};
		MsgSip::setShowBodyFor(
		    "request.method == 'INVITE' || request.method == 'MESSAGE' || request.method == 'REGISTER'");

		out.str("");
		out << invite;
		invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted == invite.msgAsString());

		out.str("");
		out << message;
		auto messagePrinted = out.str();
		BC_ASSERT_TRUE(messagePrinted == message.msgAsString());

		out.str("");
		out << registerSip;
		auto registerPrinted = out.str();
		BC_ASSERT_TRUE(registerPrinted == registerSip.msgAsString());

		out.str("");
		out << subscribe;
		auto subscribePrinted = out.str();
		BC_ASSERT_TRUE(subscribePrinted != subscribe.msgAsString());
		BC_ASSERT_TRUE(subscribePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(subscribePrinted.find("123456789") == string::npos);

		out.str("");
		out << emptySubscribe;
		auto emptySubscribePrinted = out.str();
		// Not in the list, but empty body, nothing to remove
		BC_ASSERT_TRUE(emptySubscribePrinted == emptySubscribe.msgAsString());

		/*
		 * CASE : FILTER ON CONTENT-TYPE
		 */
		MsgSip::setShowBodyFor("content-type == 'application/sdp'");

		// Invite content-type is application/sdp
		out.str("");
		out << invite;
		invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted == invite.msgAsString());

		// Message content-type is not application/sdp
		out.str("");
		out << message;
		messagePrinted = out.str();
		BC_ASSERT_TRUE(messagePrinted != message.msgAsString());
		BC_ASSERT_TRUE(messagePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(messagePrinted.find("1234") == string::npos);

		/*
		 * CASE : COMPLEX WITH CONTENT-TYPE AND METHOD
		 */
		MsgSip::setShowBodyFor("content-type == 'application/sdp' && request.method == 'MESSAGE'");

		// Invite content-type is application/sdp
		out.str("");
		out << invite;
		invitePrinted = out.str();
		BC_ASSERT_TRUE(invitePrinted != invite.msgAsString());
		BC_ASSERT_TRUE(invitePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(invitePrinted.find("v=0\r\n") == string::npos);

		// Message content-type is not application/sdp
		out.str("");
		out << message;
		messagePrinted = out.str();
		BC_ASSERT_TRUE(messagePrinted != message.msgAsString());
		BC_ASSERT_TRUE(messagePrinted.find(" bytes of body hidden]") != string::npos);
		BC_ASSERT_TRUE(messagePrinted.find("1234") == string::npos);
	}
};

namespace {
TestSuite _("MsgSip unit tests",
            {
                TEST_NO_TAG("Test the MsgSip stream insertion operator.", run<MsgSipLogTest>),
            });
}
} // namespace tester
} // namespace flexisip
