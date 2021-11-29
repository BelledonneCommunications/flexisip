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

#include "flexisip/module-pushnotification.hh"
#include "flexisip/registrardb.hh"
#include "pushnotification/firebase/firebase-client.hh"
#include "tester.hh"

using namespace std;
using namespace std::chrono;
using namespace flexisip;
using namespace flexisip::pushnotification;

static shared_ptr<sofiasip::SuRoot> root{};
static shared_ptr<Agent> agent{};

static void beforeEach() {
	root = make_shared<sofiasip::SuRoot>();
	agent = make_shared<Agent>(root);
}

static void afterEach() {
	agent->unloadConfig();
	RegistrarDb::resetDB();
	agent.reset();
	root.reset();
}

static void pushIsSentOnInvite() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_module_push.conf").c_str());
	agent->loadConfig(cfg);

	FirebaseClient::FIREBASE_ADDRESS = "randomHost";
	FirebaseClient::FIREBASE_PORT = "3000";

	// Starting Flexisip
	agent->start("", "");

	const auto& modulePush = dynamic_pointer_cast<PushNotification>(agent->findModule("PushNotification"));
	string rawRequest{
	    R"sip(INVITE sip:jean.claude@90.112.184.171:41404;pn-prid=cUNaHkG98QM:APA91bE83L4-r_EVyMXxCJHVSND_GvNRpsxp3o8FoY4oRT0f1Iv9TdNhcoLh7xp2rqY-yXkf4m0JNrbS3ZueJnTF3Xjj1MwK86qSOQ5rScM824_lJlUBy9wKwLrp0gMdSmuZPlszN-Np;pn-provider=fcm;pn-param=ARandomKey;pn-silent=1;pn-timeout=0;transport=tls;fs-conn-id=169505b723d9857 SIP/2.0
Via: SIP/2.0/TLS 192.168.1.197:49812;branch=z9hG4bK.BJKV8sLmg;rport=49812;received=151.127.31.93
Route: <sip:91.121.209.194:5059;transport=tcp;lr>
Record-Route: <sips:sip1.linphone.org:5061;lr>
Max-Forwards: 70
From: "Kijou" <sip:kijou@sip.linphone.org>;tag=08HMIWXqx
To: "Jean Claude" <sip:jean.claude@sip.linphone.org>
Call-ID: 6g7z4~lD8M
CSeq: 20 INVITE
Contact: <sip:kijou@sip.linphone.org;gr=urn:uuid:5c3651e6-3767-0091-968b-42c911ba7c7b>;+org.linphone.specs="ephemeral,groupchat,groupchat/1.1,lime"
User-Agent: LinphoneiOS/4.5.1 (iPhone de Kijou) LinphoneSDK/5.0.40-pre.2+ea19d3d
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE
Supported: replaces, outbound, gruu
Content-Type: application/sdp
Content-Length: 1081

v=0
o=kijou 2959 756 IN IP4 192.168.1.197
s=Talk
c=IN IP4 192.168.1.197
t=0 0
a=ice-pwd:fe26e5da31eb0957ad9eb1f0
a=ice-ufrag:caba7d03
a=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics
a=Ik:YgB4l8QfvS6iTr9Krd/eQHVPF/beS0cJ8YCJDKmkI2I=
m=audio 7254 RTP/AVPF 96 97 98 0 8 18 99 100 101
c=IN IP4 151.127.31.93
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 speex/16000
a=fmtp:97 vbr=on
a=rtpmap:98 speex/8000
a=fmtp:98 vbr=on
a=fmtp:18 mode=30
a=rtpmap:99 telephone-event/48000
a=rtpmap:100 telephone-event/16000
a=rtpmap:101 telephone-event/8000
a=candidate:1 1 UDP 2130706303 192.168.1.197 7254 typ host
a=candidate:1 2 UDP 2130706302 192.168.1.197 7255 typ host
a=candidate:2 1 UDP 2130706303 10.85.99.47 7254 typ host
a=candidate:2 2 UDP 2130706302 10.85.99.47 7255 typ host
a=candidate:3 1 UDP 1694498687 151.127.31.93 7254 typ srflx raddr 192.168.1.197 rport 7254
a=candidate:3 2 UDP 1694498686 151.127.31.93 7255 typ srflx raddr 192.168.1.197 rport 7255
a=rtcp-fb:* trr-int 1000
a=rtcp-fb:* ccm tmmbr)sip"};
	auto request = std::make_shared<MsgSip>(msg_make(sip_default_mclass(), 0, rawRequest.c_str(), rawRequest.size()));
	auto reqSipEvent = std::make_shared<RequestSipEvent>(agent, request);
	reqSipEvent->setOutgoingAgent(agent);
	reqSipEvent->createOutgoingTransaction();

	modulePush->onRequest(reqSipEvent);

	auto beforePlus2 = system_clock::now() + 2s;
	while (beforePlus2 >= system_clock::now() && modulePush->getService().getFailedCounter()->read() != 1) {
		root->step(100ms);
	}

	BC_ASSERT_EQUAL(modulePush->getService().getFailedCounter()->read(), 1, int, "%i");
}

static void pushIsNotSentOnInviteWithReplacesHeader() {
	// Agent initialization
	auto cfg = GenericManager::get();
	cfg->load(string(TESTER_DATA_DIR).append("/config/flexisip_module_push.conf").c_str());
	agent->loadConfig(cfg);

	FirebaseClient::FIREBASE_ADDRESS = "randomHost";
	FirebaseClient::FIREBASE_PORT = "3000";

	// Starting Flexisip
	agent->start("", "");

	const auto& modulePush = dynamic_pointer_cast<PushNotification>(agent->findModule("PushNotification"));
	string rawRequest{
	    R"sip(INVITE sip:jean.claude@90.112.184.171:41404;pn-prid=cUNaHkG98QM:APA91bE83L4-r_EVyMXxCJHVSND_GvNRpsxp3o8FoY4oRT0f1Iv9TdNhcoLh7xp2rqY-yXkf4m0JNrbS3ZueJnTF3Xjj1MwK86qSOQ5rScM824_lJlUBy9wKwLrp0gMdSmuZPlszN-Np;pn-provider=fcm;pn-param=ARandomKey;pn-silent=1;pn-timeout=0;transport=tls;fs-conn-id=169505b723d9857 SIP/2.0
Via: SIP/2.0/TLS 192.168.1.197:49812;branch=z9hG4bK.BJKV8sLmg;rport=49812;received=151.127.31.93
Route: <sip:91.121.209.194:5059;transport=tcp;lr>
Record-Route: <sips:sip1.linphone.org:5061;lr>
Max-Forwards: 70
From: "Kijou" <sip:kijou@sip.linphone.org>;tag=08HMIWXqx
To: "Jean Claude" <sip:jean.claude@sip.linphone.org>
Call-ID: 6g7z4~lD8M
CSeq: 20 INVITE
Contact: <sip:kijou@sip.linphone.org;gr=urn:uuid:5c3651e6-3767-0091-968b-42c911ba7c7b>;+org.linphone.specs="ephemeral,groupchat,groupchat/1.1,lime"
User-Agent: LinphoneiOS/4.5.1 (iPhone de Kijou) LinphoneSDK/5.0.40-pre.2+ea19d3d
Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, SUBSCRIBE, INFO, PRACK, UPDATE
Supported: replaces, outbound, gruu
Replaces: 6g7z4~lD7M
Content-Type: application/sdp
Content-Length: 1081

v=0
o=kijou 2959 756 IN IP4 192.168.1.197
s=Talk
c=IN IP4 192.168.1.197
t=0 0
a=ice-pwd:fe26e5da31eb0957ad9eb1f0
a=ice-ufrag:caba7d03
a=rtcp-xr:rcvr-rtt=all:10000 stat-summary=loss,dup,jitt,TTL voip-metrics
a=Ik:YgB4l8QfvS6iTr9Krd/eQHVPF/beS0cJ8YCJDKmkI2I=
m=audio 7254 RTP/AVPF 96 97 98 0 8 18 99 100 101
c=IN IP4 151.127.31.93
a=rtpmap:96 opus/48000/2
a=fmtp:96 useinbandfec=1
a=rtpmap:97 speex/16000
a=fmtp:97 vbr=on
a=rtpmap:98 speex/8000
a=fmtp:98 vbr=on
a=fmtp:18 mode=30
a=rtpmap:99 telephone-event/48000
a=rtpmap:100 telephone-event/16000
a=rtpmap:101 telephone-event/8000
a=candidate:1 1 UDP 2130706303 192.168.1.197 7254 typ host
a=candidate:1 2 UDP 2130706302 192.168.1.197 7255 typ host
a=candidate:2 1 UDP 2130706303 10.85.99.47 7254 typ host
a=candidate:2 2 UDP 2130706302 10.85.99.47 7255 typ host
a=candidate:3 1 UDP 1694498687 151.127.31.93 7254 typ srflx raddr 192.168.1.197 rport 7254
a=candidate:3 2 UDP 1694498686 151.127.31.93 7255 typ srflx raddr 192.168.1.197 rport 7255
a=rtcp-fb:* trr-int 1000
a=rtcp-fb:* ccm tmmbr)sip"};
	auto request = std::make_shared<MsgSip>(msg_make(sip_default_mclass(), 0, rawRequest.c_str(), rawRequest.size()));
	auto reqSipEvent = std::make_shared<RequestSipEvent>(agent, request);
	reqSipEvent->setOutgoingAgent(agent);
	reqSipEvent->createOutgoingTransaction();

	modulePush->onRequest(reqSipEvent);

	auto beforePlus2 = system_clock::now() + 2s;
	while (beforePlus2 >= system_clock::now() && beforePlus2 >= system_clock::now() &&
	       modulePush->getService().getFailedCounter()->read() != 1) {
		root->step(100ms);
	}

	BC_ASSERT_EQUAL(modulePush->getService().getSentCounter()->read(), 0, int, "%i");
	BC_ASSERT_EQUAL(modulePush->getService().getFailedCounter()->read(), 0, int, "%i");
}

static test_t tests[] = {
    TEST_NO_TAG("Push is sent on Invite", pushIsSentOnInvite),
    TEST_NO_TAG("Push is not sent on Invite with Replaces Header", pushIsNotSentOnInviteWithReplacesHeader),
};

test_suite_t module_pushnitification_suite = {"Module push-notification",       nullptr, nullptr, beforeEach, afterEach,
                                              sizeof(tests) / sizeof(tests[0]), tests};