/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#pragma once

#include <functional>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>

#include <sofia-sip/sdp.h>
#include <sofia-sip/sip.h>

#include "ortp/payloadtype.h"

#include <flexisip/common.hh>

#define payload_type_set_number(pt, n) (pt)->user_data = (void*)(long)n
#define payload_type_get_number(pt) (int)(long)(pt)->user_data

namespace flexisip {

struct RelayTransport {
	std::string mIpv6Address;     // The Ipv6 address advertised in SDP.
	std::string mIpv4Address;     // The Ipv4 address advertised in SDP.
	std::string mIpv6BindAddress; // The ipv6 address used for bind(). WARNING: if set to anything else than "::0", dual
	                              // stack will not work !
	std::string mIpv4BindAddress;
	int mPreferredFamily = AF_INET; // or AF_INET6.
	int mRtpPort = 0;
	int mRtcpPort = 0;
	bool mDualStackRequired = true;
};

class SdpMasqueradeContext {
public:
	enum IceState { IceNone, IceOffered, IceCompleted } mIceState;
	SdpMasqueradeContext();
	bool updateIceFromOffer(sdp_session_t* session, sdp_media_t* mline, bool isOfferer);
	bool updateIceFromAnswer(sdp_session_t* session, sdp_media_t* mline, bool isOfferer);
	IceState getState() const {
		return mIceState;
	}

private:
	std::string mIceUfrag, mIcePasswd;
	static std::string getAttribute(sdp_session_t* session, sdp_media_t* mline, const std::string& name);
	static const char* toString(IceState state);
	static bool hasCandidates(sdp_media_t* mline);
	static bool hasRemoteCandidates(sdp_media_t* mline);
};

struct MasqueradeContextPair {
	MasqueradeContextPair(const std::shared_ptr<SdpMasqueradeContext>& offerer,
	                      const std::shared_ptr<SdpMasqueradeContext>& offered)
	    : mOfferer(offerer), mOffered(offered) {
	}
	std::shared_ptr<SdpMasqueradeContext> mOfferer;
	std::shared_ptr<SdpMasqueradeContext> mOffered;
	bool valid() const {
		return mOfferer != NULL && mOffered != NULL;
	}
};

/**
 * Utility class used to do various changes in an existing SDP message.
 **/
class SdpModifier {
public:
	static std::shared_ptr<SdpModifier>
	createFromSipMsg(su_home_t* home, sip_t* sip, const std::string& nortproxy = "");
	static bool hasSdp(const sip_t* sip);
	bool initFromSipMsg(sip_t* sip);
	std::list<PayloadType*> readPayloads();
	void replacePayloads(const std::list<PayloadType*>& payloads, const std::list<PayloadType*>& preserved_numbers);
	static std::list<PayloadType*>
	findCommon(const std::list<PayloadType*>& offer, const std::list<PayloadType*>& answer, bool use_offer_numbering);
	int readPtime();
	short getAudioIpVersion();
	void getAudioIpPort(std::string* ip, int* port);
	void changeAudioIpPort(const char* ip, int port);
	void changeConnection(sdp_connection_t* c, const char* ip);
	void changeMediaConnection(sdp_media_t* mline, const char* relay_ip, bool isIP6);
	void addIceCandidateInOffer(std::function<const RelayTransport*(int)> getRelayAddrFcn,
	                            std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
	                            std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
	                            bool forceRelay);
	void addIceCandidateInAnswer(std::function<const RelayTransport*(int)> getRelayAddrFcn,
	                             std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
	                             std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
	                             bool forceRelay);
	void iterateInOffer(std::function<void(int, const std::string&, int, int)>);
	void iterateInAnswer(std::function<void(int, const std::string&, int, int)>);
	void masqueradeInOffer(std::function<const RelayTransport*(int)> getAddrFcn);
	void masqueradeInAnswer(std::function<const RelayTransport*(int)> getAddrFcn);
	void addAttribute(const char* name, const char* value);
	bool hasAttribute(const char* name);
	void addMediaAttribute(sdp_media_t* mline, const char* name, const char* value);
	bool hasMediaAttribute(sdp_media_t* mline, const char* name);
	bool hasIceCandidate(sdp_media_t* mline, const std::string& addr, int port);
	int update(msg_t* msg, sip_t* sip);
	void setPtime(int ptime);
	virtual ~SdpModifier();
	SdpModifier(su_home_t* home, std::string nortproxy);
	sdp_session_t* mSession;
	sip_t* mSip;

private:
	void addIceCandidate(std::function<const RelayTransport*(int)> getRelayAddrFcn,
	                     std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
	                     std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
	                     bool isOffer,
	                     bool forceRelay);
	void iterate(std::function<void(int, const std::string&, int, int)>);
	void masquerade(std::function<const RelayTransport*(int)> getAddrFcn);
	void changeRtcpAttr(sdp_media_t* mline, const std::string& relayAddr, int port, bool ipv6);
	sdp_parser_t* mParser;
	su_home_t* mHome;
	std::string mNortproxy;
};

} // namespace flexisip