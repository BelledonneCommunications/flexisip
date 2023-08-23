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

#include "sdp-modifier.hh"

#include <ortp/payloadtype.h>
#include <sofia-sip/sip_protos.h>
#include <sstream>
#include <string_view>

using namespace std;
using namespace flexisip;

SdpMasqueradeContext::SdpMasqueradeContext() {
	mIceState = IceNone;
}

const char* SdpMasqueradeContext::toString(SdpMasqueradeContext::IceState state) {
	switch (state) {
		case IceNone:
			return "IceNone";
		case IceOffered:
			return "IceOffered";
		case IceCompleted:
			return "IceCompleted";
	}
	return "IceBug";
}

string SdpMasqueradeContext::getAttribute(sdp_session_t* session, sdp_media_t* mline, const string& name) {
	sdp_attribute_t* attr = sdp_attribute_find(mline->m_attributes, name.c_str());
	if (attr && attr->a_value) return attr->a_value;
	attr = sdp_attribute_find(session->sdp_attributes, name.c_str());
	if (attr && attr->a_value) return attr->a_value;
	return "";
}

bool SdpMasqueradeContext::hasCandidates(sdp_media_t* mline) {
	return sdp_attribute_find(mline->m_attributes, "candidate") != NULL;
}

bool SdpMasqueradeContext::hasRemoteCandidates(sdp_media_t* mline) {
	return sdp_attribute_find(mline->m_attributes, "remote-candidates") != NULL;
}

bool SdpMasqueradeContext::updateIceFromOffer(sdp_session_t* session, sdp_media_t* mline, bool isOfferer) {
	string ufrag, passwd;
	IceState oldState = mIceState;
	bool needsCandidates = false;

	ufrag = getAttribute(session, mline, "ice-ufrag");
	passwd = getAttribute(session, mline, "ice-pwd");

	if (isOfferer) {
		switch (mIceState) {
			case IceNone:
				if (!ufrag.empty() && !passwd.empty()) {
					if (hasRemoteCandidates(mline)) {
						/*This should not happen. We are discovering an already established ice session.*/
						mIceState = IceCompleted;
						needsCandidates = false;
						LOGE("Unexpected remote-candidates in SDP offer.");
					} else if (hasCandidates(mline)) {
						mIceState = IceOffered;
						needsCandidates = true;
					}
				}
				break;
			case IceOffered:
				needsCandidates = true;
				break;
			case IceCompleted:
				needsCandidates = false;
				if ((ufrag != mIceUfrag || passwd != mIcePasswd) && hasCandidates(mline)) {
					/*ICE restart*/
					mIceState = IceOffered;
					needsCandidates = true;
					LOGD("Ice restart detected ufrag %s->%s pwd %s->%s", mIceUfrag.c_str(), ufrag.c_str(),
					     mIcePasswd.c_str(), passwd.c_str());
				} else if (!hasCandidates(mline)) {
					/*case of a stream that is put inactive*/
					mIceState = IceNone;
				}
				break;
		}
		mIceUfrag = ufrag;
		mIcePasswd = passwd;
		LOGD("updateIceFromOffer() this=%p setting ufrag, pwd to %s %s", this, ufrag.c_str(), passwd.c_str());
	} else {
		switch (mIceState) {
			case IceNone:
				if (!ufrag.empty() && !passwd.empty() && hasCandidates(mline)) {
					mIceState = IceOffered;
					needsCandidates = true;
				}
				break;
			case IceOffered:
			case IceCompleted:
				if (!hasCandidates(mline)) {
					/*case of a stream that is put inactive*/
					mIceState = IceNone;
				}
				break;
		}
	}
	LOGD("updateIceFromOffer() this=%p %s state %s -> %s", this, isOfferer ? "offerer" : "offered", toString(oldState),
	     toString(mIceState));
	return needsCandidates;
}

bool SdpMasqueradeContext::updateIceFromAnswer(sdp_session_t* session, sdp_media_t* mline, bool isOfferer) {
	string ufrag, passwd;
	IceState oldState = mIceState;
	bool needsCandidates = false;

	ufrag = getAttribute(session, mline, "ice-ufrag");
	passwd = getAttribute(session, mline, "ice-pwd");

	if (isOfferer) {
		switch (mIceState) {
			case IceNone:
				break;
			case IceOffered:
				if (!ufrag.empty() && !passwd.empty() && hasCandidates(mline)) {
					mIceState = IceCompleted;
				}
				break;
			case IceCompleted:
				/*case of a stream that is declined*/
				if (!hasCandidates(mline)) mIceState = IceNone;
				break;
		}
	} else {
		switch (mIceState) {
			case IceNone:
				break;
			case IceOffered:
				if (!ufrag.empty() && !passwd.empty() && hasCandidates(mline)) {
					mIceState = IceCompleted;
					needsCandidates = true;
				}
				break;
			case IceCompleted:
				if (!hasCandidates(mline)) {
					/*case of a stream that is declined*/
					mIceState = IceNone;
				} else if (ufrag != mIceUfrag || passwd != mIcePasswd) {
					/*ICE restart*/
					mIceState = IceCompleted; /* no op*/
					needsCandidates = true;
					LOGD("Ice restart detected ufrag %s->%s pwd %s->%s", mIceUfrag.c_str(), ufrag.c_str(),
					     mIcePasswd.c_str(), passwd.c_str());
				}
				break;
		}
		mIceUfrag = ufrag;
		mIcePasswd = passwd;
		LOGD("updateIceFromAnswer() this=%p setting ufrag, pwd to %s %s", this, ufrag.c_str(), passwd.c_str());
	}
	LOGD("updateIceFromAnswer() this=%p %s state %s -> %s", this, isOfferer ? "offerer" : "offered", toString(oldState),
	     toString(mIceState));
	return needsCandidates;
}

shared_ptr<SdpModifier> SdpModifier::createFromSipMsg(su_home_t* home, sip_t* sip, const string& nortproxy) {
	if (!sip->sip_payload || !sip->sip_payload->pl_data) return shared_ptr<SdpModifier>();
	auto sm = make_shared<SdpModifier>(home, nortproxy);
	if (!sm->initFromSipMsg(sip)) {
		sm.reset();
	}
	return sm;
}

bool SdpModifier::hasSdp(const sip_t* sip) {
	sip_payload_t* payload = sip->sip_payload;
	if (payload == NULL || payload->pl_data == NULL) {
		return false;
	}
	return true;
}

bool SdpModifier::initFromSipMsg(sip_t* sip) {
	sip_payload_t* payload = sip->sip_payload;
	if (payload == NULL || payload->pl_data == NULL) {
		LOGW("SIP message has no payload");
		return false;
	}
	mParser = sdp_parse(mHome, payload->pl_data, (int)payload->pl_len, 0);
	mSession = sdp_session(mParser);
	if (mSession == NULL) {
		LOGW("SDP parsing error: %s", sdp_parsing_error(mParser));
		return false;
	}
	if (mSession->sdp_media == NULL) {
		LOGW("SDP with no mline.");
		return false;
	}
	mSip = sip;
	return true;
}

SdpModifier::SdpModifier(su_home_t* home, std::string nortproxy) : mHome(home), mNortproxy(nortproxy) {
	mParser = NULL;
	mSip = NULL;
	mSession = NULL;
}

SdpModifier::~SdpModifier() {
	if (mParser) sdp_parser_free(mParser);
}

/*
static sdp_list_t *sdp_list_append(su_home_t *home, sdp_list_t *l, char *text){
    sdp_list_t *elem=(sdp_list_t*)su_zalloc(home,sizeof(sdp_list_t));
    sdp_list_t *begin=l;
    elem->l_size=sizeof(sdp_list_t);
    elem->l_text=text;
    if (l==NULL) return elem;
    while(l->l_next!=NULL) l=l->l_next;
    l->l_next=elem;
    return begin;
}
*/

static PayloadType* payload_type_make_from_sdp_rtpmap(sdp_rtpmap_t* rtpmap) {
	if (rtpmap->rm_rate == 0 || rtpmap->rm_encoding == NULL) {
		LOGE("Bad media description for payload type : %i", rtpmap->rm_pt);
		return NULL;
	}
	PayloadType* pt = payload_type_new();
	pt->type = PAYLOAD_AUDIO_PACKETIZED;
	pt->mime_type = strdup(rtpmap->rm_encoding);
	pt->clock_rate = rtpmap->rm_rate;
	payload_type_set_number(pt, rtpmap->rm_pt);
	payload_type_set_send_fmtp(pt, rtpmap->rm_fmtp);
	return pt;
}

static sdp_rtpmap_t* sdp_rtpmap_make_from_payload_type(su_home_t* home, PayloadType* pt, int number) {
	sdp_rtpmap_t* map = (sdp_rtpmap_t*)su_zalloc(home, sizeof(sdp_rtpmap_t));
	map->rm_size = sizeof(sdp_rtpmap_t);
	map->rm_encoding = su_strdup(home, pt->mime_type);
	map->rm_rate = (unsigned long)pt->clock_rate;
	map->rm_pt = (unsigned int)number;
	map->rm_fmtp = su_strdup(home, pt->recv_fmtp);
	return map;
}

static sdp_rtpmap_t* sdp_rtpmap_append(sdp_rtpmap_t* rtpmaps, sdp_rtpmap_t* newmap) {
	sdp_rtpmap_t* begin = rtpmaps;
	if (rtpmaps == NULL) return newmap;
	while (rtpmaps->rm_next) {
		rtpmaps = rtpmaps->rm_next;
	}
	rtpmaps->rm_next = newmap;
	return begin;
}
/*
static sdp_rtpmap_t *sdp_rtpmaps_find_by_number(sdp_rtpmap_t *rtpmaps, int number){
    sdp_rtpmap_t *elem;
    for(elem=rtpmaps;elem!=NULL;elem=elem->rm_next){
        if (elem->rm_pt==(unsigned int)number)
            return elem;
    }
    return NULL;
}
*/

static PayloadType* find_by_number(const std::list<PayloadType*>& payloads, int number) {
	for (auto elem = payloads.cbegin(); elem != payloads.cend(); ++elem) {
		PayloadType* pt = *elem;
		if (payload_type_get_number(pt) == number) return pt;
	}
	return NULL;
}

static PayloadType* find_payload(const std::list<PayloadType*>& payloads, const char* mime, int rate) {
	for (auto elem = payloads.cbegin(); elem != payloads.cend(); ++elem) {
		PayloadType* pt = *elem;
		if (strcasecmp(pt->mime_type, mime) == 0 && rate == pt->clock_rate) return pt;
	}
	return NULL;
}

list<PayloadType*> SdpModifier::readPayloads() {
	sdp_media_t* mline = mSession->sdp_media;
	sdp_rtpmap_t* elem = mline->m_rtpmaps;
	list<PayloadType*> ret;
	for (; elem != NULL; elem = elem->rm_next) {
		PayloadType* pt = payload_type_make_from_sdp_rtpmap(elem);
		if (pt != NULL) ret.push_back(pt);
	}
	return ret;
}

std::list<PayloadType*> SdpModifier::findCommon(const std::list<PayloadType*>& offer,
                                                const std::list<PayloadType*>& answer,
                                                bool use_offer_numbering) {
	std::list<PayloadType*> ret;
	for (auto e1 = offer.cbegin(); e1 != offer.cend(); ++e1) {
		PayloadType* pt1 = *e1;
		for (auto e2 = answer.cbegin(); e2 != answer.cend(); ++e2) {
			PayloadType* pt2 = *e2;
			if (strcasecmp(pt1->mime_type, pt2->mime_type) == 0 && pt1->clock_rate == pt2->clock_rate) {
				PayloadType* found = payload_type_clone(pt2);
				if (use_offer_numbering) payload_type_set_number(found, payload_type_get_number(pt1));
				else payload_type_set_number(found, payload_type_get_number(pt2));
				ret.push_back(found);
			}
		}
	}
	return ret;
}

void SdpModifier::replacePayloads(const std::list<PayloadType*>& payloads,
                                  const std::list<PayloadType*>& preserved_numbers) {
	PayloadType* pt;
	sdp_rtpmap_t ref;
	int pt_index = 100;

	memset(&ref, 0, sizeof(ref));
	ref.rm_size = sizeof(ref);

	sdp_media_t* mline = mSession->sdp_media;
	mline->m_rtpmaps = NULL;

	for (auto elem = payloads.cbegin(); elem != payloads.cend(); ++elem) {
		pt = *elem;
		ref.rm_encoding = pt->mime_type;
		ref.rm_rate = (unsigned long)pt->clock_rate;
		LOGD("Adding new payload to sdp: %s/%i", pt->mime_type, pt->clock_rate);
		int number = payload_type_get_number(pt);
		if (number == -1) {
			/*see if it was numbered in the original offer*/
			PayloadType* orig = find_payload(preserved_numbers, pt->mime_type, pt->clock_rate);
			if (orig) {
				number = payload_type_get_number(orig);
			} else {
				/* find a dynamic  payload type number */
				for (; pt_index < 127; ++pt_index) {
					if (find_by_number(preserved_numbers, pt_index) == NULL) {
						number = pt_index;
						++pt_index;
						break;
					}
				}
			}
		}
		sdp_rtpmap_t* map = sdp_rtpmap_make_from_payload_type(mHome, pt, number);
		mline->m_rtpmaps = sdp_rtpmap_append(mline->m_rtpmaps, map);
	}
}

int SdpModifier::readPtime() {
	sdp_media_t* mline = mSession->sdp_media;
	if (mline && mline->m_attributes) {
		sdp_attribute_t* at = sdp_attribute_find(mline->m_attributes, "ptime");
		if (at && at->a_value) {
			return atoi(at->a_value);
		}
	}
	return 0;
}

void SdpModifier::setPtime(int ptime) {
	sdp_media_t* mline = mSession->sdp_media;
	if (mline && mline->m_attributes) {
		if (ptime > 0) {
			sdp_attribute_t* at = sdp_attribute_find(mline->m_attributes, "ptime");
			if (at) {
				at->a_value = su_sprintf(mHome, "%i", ptime);
			} else {
				sdp_attribute_t* cat = (sdp_attribute_t*)su_alloc(mHome, sizeof(sdp_attribute_t));
				memset(cat, 0, sizeof(*cat));
				cat->a_size = sizeof(*cat);
				cat->a_name = "ptime";
				cat->a_value = su_sprintf(mHome, "%i", ptime);
				sdp_attribute_append(&mline->m_attributes, cat);
			}
		} else {
			sdp_attribute_remove(&mline->m_attributes, "ptime");
		}
	}
}

short SdpModifier::getAudioIpVersion() {
	sdp_connection_t* c = mSession->sdp_media->m_connections;
	if (c && c->c_addrtype == sdp_addr_ip6) return 6;
	return 4;
}

void SdpModifier::getAudioIpPort(string* ip, int* port) {
	*ip = mSession->sdp_media->m_connections ? mSession->sdp_media->m_connections->c_address
	                                         : mSession->sdp_connection->c_address;
	*port = mSession->sdp_media->m_port;
}

void SdpModifier::changeAudioIpPort(const char* ip, int port) {
	mSession->sdp_media->m_connections ? mSession->sdp_media->m_connections->c_address = su_strdup(mHome, ip)
	                                   : mSession->sdp_connection->c_address = su_strdup(mHome, ip);
	mSession->sdp_media->m_port = (unsigned long)port;
}

void SdpModifier::changeMediaConnection(sdp_media_t* mline, const char* relay_ip, bool isIP6) {
	sdp_connection_t* c = sdp_connection_dup(mHome, mSession->sdp_connection);
	if (c == NULL) {
		if (mline->m_connections) {
			mline->m_connections->c_address = su_strdup(mHome, relay_ip);
			mline->m_connections->c_addrtype = isIP6 ? sdp_addr_ip6 : sdp_addr_ip4;
		}
	} else {
		c->c_addrtype = isIP6 ? sdp_addr_ip6 : sdp_addr_ip4;
		c->c_address = su_strdup(mHome, relay_ip);
		if (sdp_connection_cmp(mSession->sdp_connection, c)) {
			mline->m_connections = c;
		} else {
			mline->m_connections = NULL;
			su_free(mHome, c);
		}
	}
}

void SdpModifier::addIceCandidate(std::function<const RelayTransport*(int)> getRelayAddrFcn,
                                  std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
                                  std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
                                  bool isOffer,
                                  bool forceRelay) {
	char foundation[32];
	sdp_media_t* mline = mSession->sdp_media;
	uint64_t r;
	int i;
	string global_c_address;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address)
		global_c_address = mSession->sdp_connection->c_address;

	r = (((uint64_t)random()) << 32) | (((uint64_t)random()) & 0xffffffff);
	snprintf(foundation, sizeof(foundation), "%llx", (long long unsigned int)r);
	for (i = 0; mline != NULL; mline = mline->m_next, ++i) {
		MasqueradeContextPair mctxs = getMasqueradeContexts(i);
		bool needsCandidates = false;

		if (mctxs.valid()) {
			if (isOffer) {
				needsCandidates = mctxs.mOfferer->updateIceFromOffer(mSession, mline, true);
				mctxs.mOffered->updateIceFromOffer(mSession, mline, false);
			} else {
				mctxs.mOfferer->updateIceFromAnswer(mSession, mline, true);
				needsCandidates = mctxs.mOffered->updateIceFromAnswer(mSession, mline, false);
			}
		}

		if (hasMediaAttribute(mline, mNortproxy.c_str())) continue;
		if (mline->m_port == 0) continue; // case of a declined or removed stream

		if (needsCandidates) {
			uint32_t priority;
			const RelayTransport* rt = getRelayAddrFcn(i);
			auto destAddr = getDestAddrFcn(i);

			if (!rt) continue;
			bool isIP6 = rt->mPreferredFamily == AF_INET6;
			string relayAddr = isIP6 ? rt->mIpv6Address : rt->mIpv4Address;

			if (forceRelay) {
				/* Masquerade c line and port for non-ICE clients.
				 Ice-enabled targets don't need this.*/
				changeMediaConnection(mline, relayAddr.c_str(), isIP6);
				mline->m_port = (unsigned long)rt->mRtpPort;
				changeRtcpAttr(mline, relayAddr, rt->mRtcpPort, isIP6);
			}
			LOGD("rt= %s %s", rt->mIpv6Address.c_str(), rt->mIpv4Address.c_str());

			for (uint16_t componentID = 1; componentID <= 2; componentID++) {
				int port = componentID == 1 ? rt->mRtpPort : rt->mRtcpPort;

				// Add IPv6 relay candidate.
				relayAddr = rt->mIpv6Address;
				if (!relayAddr.empty() && !hasIceCandidate(mline, relayAddr.c_str(), port)) {
					priority = (65535 << 8) | (256 - componentID);
					ostringstream candidate_line;
					candidate_line << foundation << ' ' << componentID << " UDP " << priority << ' '
					               << relayAddr.c_str() << ' ' << port << " typ relay raddr " << std::get<0>(destAddr)
					               << " rport " << (componentID == 1 ? std::get<1>(destAddr) : std::get<2>(destAddr));
					addMediaAttribute(mline, "candidate", candidate_line.str().c_str());
				}
				// Add IPv4 relay candidate
				relayAddr = rt->mIpv4Address;
				if (!relayAddr.empty() && !hasIceCandidate(mline, relayAddr.c_str(), port)) {
					priority = (65535 << 8) | (256 - componentID);
					ostringstream candidate_line;
					candidate_line << foundation << ' ' << componentID << " UDP " << priority << ' '
					               << relayAddr.c_str() << ' ' << port << " typ relay raddr " << std::get<0>(destAddr)
					               << " rport " << (componentID == 1 ? std::get<1>(destAddr) : std::get<2>(destAddr));
					addMediaAttribute(mline, "candidate", candidate_line.str().c_str());
				}
			}
			if (!mNortproxy.empty()) addMediaAttribute(mline, mNortproxy.c_str(), "yes");
		}
	}
}

void SdpModifier::addIceCandidateInOffer(std::function<const RelayTransport*(int)> getRelayAddrFcn,
                                         std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
                                         std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
                                         bool forceRelay) {
	addIceCandidate(getRelayAddrFcn, getDestAddrFcn, getMasqueradeContexts, true, forceRelay);
}

void SdpModifier::addIceCandidateInAnswer(std::function<const RelayTransport*(int)> getRelayAddrFcn,
                                          std::function<std::tuple<std::string, int, int>(int)> getDestAddrFcn,
                                          std::function<MasqueradeContextPair(int)> getMasqueradeContexts,
                                          bool forceRelay) {
	addIceCandidate(getRelayAddrFcn, getDestAddrFcn, getMasqueradeContexts, false, forceRelay);
}

void SdpModifier::cleanUpIceCandidatesInAnswer(std::function<MasqueradeContextPair(int)> getMasqueradeContexts) {
	auto mline = mSession->sdp_media;
	for (auto i = 0; mline != NULL; mline = mline->m_next, ++i) {
		const auto offerer = getMasqueradeContexts(i).mOfferer;
		if (!offerer) continue;

		// If there weren't any ICE candidates in the offer, remove any candidates from the answer
		if (offerer->mIceState == SdpMasqueradeContext::IceNone) {
			removeMediaAttributes(mline, "candidate");
		}
	}
}

void SdpModifier::iterate(function<void(int, const string&, int, int)> fct) {
	sdp_media_t* mline = mSession->sdp_media;
	int i;
	string global_c_address;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address)
		global_c_address = mSession->sdp_connection->c_address;

	for (i = 0; mline != NULL; mline = mline->m_next, ++i) {
		string ip = (mline->m_connections && mline->m_connections->c_address) ? mline->m_connections->c_address
		                                                                      : global_c_address;
		int port = mline->m_port;
		int rtcp_port = port != 0 ? port + 1 : 0;
		if (hasMediaAttribute(mline, mNortproxy.c_str())) continue;

		sdp_attribute_t* a_rtcp = sdp_attribute_find(mline->m_attributes, "rtcp");
		if (a_rtcp && a_rtcp->a_value) {
			istringstream ist(string(a_rtcp->a_value));
			ist >> rtcp_port;
		}
		fct(i, ip, port, rtcp_port);
	}
}

void SdpModifier::iterateInOffer(function<void(int, const string&, int, int)> fct) {
	iterate(fct);
}

void SdpModifier::iterateInAnswer(function<void(int, const string&, int, int)> fct) {
	iterate(fct);
}

void SdpModifier::changeConnection(sdp_connection_t* c, const char* ip) {
	/* set the c= ip address as told in 'ip' argument, except if it was 0.0.0.0, for compatibility with old softphone
	 * indicating a send-only stream using this technique*/
	if (c->c_address && strcmp(c->c_address, "0.0.0.0") == 0) {
		return;
	}
	bool isIP6 = strchr(ip, ':') != NULL;
	c->c_address = su_strdup(mHome, ip);
	c->c_addrtype = isIP6 ? sdp_addr_ip6 : sdp_addr_ip4;
}

void SdpModifier::changeRtcpAttr(sdp_media_t* mline, const string& relayAddr, int port, bool ipv6) {
	sdp_attribute_t* rtcp_attribute = sdp_attribute_find(mline->m_attributes, "rtcp");
	if (rtcp_attribute) {
		int previous_port;
		string ip_version, network_family, protocol, rtcp_addr;
		ostringstream ost;
		ost << port;
		istringstream ist(string(rtcp_attribute->a_value));
		ist >> previous_port;
		if (!ist.eof()) ist >> network_family;
		if (!ist.fail() && !ist.eof()) ist >> protocol;
		if (!ist.fail() && !ist.eof()) ist >> rtcp_addr;
		if (!ist.fail() && !ist.eof()) {
			ost << ' ' << network_family << ' ' << (ipv6 ? "IP6" : "IP4") << ' ' << relayAddr;
		}
		sdp_attribute_t* a = (sdp_attribute_t*)su_alloc(mHome, sizeof(sdp_attribute_t));
		memset(a, 0, sizeof(*a));
		a->a_size = sizeof(*a);
		a->a_name = su_strdup(mHome, "rtcp");
		a->a_value = su_strdup(mHome, ost.str().c_str());
		sdp_attribute_replace(&mline->m_attributes, a, 0);
	}
}

void SdpModifier::masquerade(function<const RelayTransport*(int)> fct) {
	sdp_media_t* mline = mSession->sdp_media;
	int i;
	string global_c_address;
	bool sdp_connection_translated = false;

	if (mSession->sdp_connection && mSession->sdp_connection->c_address)
		global_c_address = mSession->sdp_connection->c_address;

	for (i = 0; mline != NULL; mline = mline->m_next, ++i) {
		if (mline->m_port == 0) continue;
		if (hasMediaAttribute(mline, "candidate")) continue; /*only masquerade if ICE is not involved*/

		if (hasMediaAttribute(mline, mNortproxy.c_str())) continue;
		const RelayTransport* rt = fct(i);

		if (!rt) continue;
		bool isIP6 = rt->mPreferredFamily == AF_INET6;
		const string& relayAddr = isIP6 ? rt->mIpv6Address : rt->mIpv4Address;

		if (mline->m_connections) {
			changeConnection(mline->m_connections, relayAddr.c_str());
		} else if (mSession->sdp_connection) {
			if (sdp_connection_translated) {
				// If the global connection has already been translated, add a media specific connection if needed
				changeMediaConnection(mline, relayAddr.c_str(), isIP6);
			} else {
				changeConnection(mSession->sdp_connection, relayAddr.c_str());
				sdp_connection_translated = true;
			}
		}
		mline->m_port = (unsigned long)rt->mRtpPort;
		changeRtcpAttr(mline, relayAddr, rt->mRtcpPort, isIP6);
	}

	if (sdp_connection_translated) {
		/* By changing the global connection address we may have broken the connection address of some mlines
		   that were marked as "nortpproxy". So we need to fix the connection address of these mlines now. */
		mline = mSession->sdp_media;
		for (i = 0; mline != NULL; mline = mline->m_next, ++i) {
			if (hasMediaAttribute(mline, mNortproxy.c_str()) && !mline->m_connections) {
				changeMediaConnection(mline, global_c_address.c_str(),
				                      strchr(global_c_address.c_str(), ':') != nullptr);
			}
		}
	}
}

void SdpModifier::masqueradeInOffer(std::function<const RelayTransport*(int)> getAddrFcn) {
	masquerade(getAddrFcn);
}

void SdpModifier::masqueradeInAnswer(std::function<const RelayTransport*(int)> getAddrFcn) {
	masquerade(getAddrFcn);
}

bool SdpModifier::hasAttribute(const char* name) {
	return sdp_attribute_find(mSession->sdp_attributes, name);
}

bool SdpModifier::hasMediaAttribute(sdp_media_t* mline, const char* name) {
	return sdp_attribute_find(mline->m_attributes, name);
}
void SdpModifier::removeMediaAttributes(sdp_media_t* mline, std::string_view name) {
	auto chainLink = &mline->m_attributes;
	for (auto attribute = *chainLink; attribute; attribute = attribute->a_next) {
		if (attribute->a_name == name) {
			// Break and re-link
			*chainLink = attribute->a_next;
		} else {
			// Advance the link
			chainLink = &attribute->a_next;
		}
	}
}

bool SdpModifier::hasIceCandidate(sdp_media_t* mline, const string& addr, int port) {
	sdp_attribute_t* candidate = mline->m_attributes;

	while ((candidate = sdp_attribute_find(candidate, "candidate")) != NULL) {
		string foundation, protocol, candidate_addr, type;
		int componentID, candidate_port;
		uint32_t priority;
		istringstream stream(string(candidate->a_value));
		stream >> foundation;
		stream >> componentID;
		stream >> protocol;
		stream >> priority;
		stream >> candidate_addr;
		stream >> candidate_port;
		stream >> type;
		if ((candidate_port == port) && (addr.compare(candidate_addr) == 0)) return true;
		candidate = candidate->a_next;
	}
	return false;
}

void SdpModifier::addAttribute(const char* name, const char* value) {
	sdp_attribute_t* a = (sdp_attribute_t*)su_alloc(mHome, sizeof(sdp_attribute_t));
	memset(a, 0, sizeof(*a));
	a->a_size = sizeof(*a);
	a->a_name = su_strdup(mHome, name);
	a->a_value = su_strdup(mHome, value);
	sdp_attribute_append(&mSession->sdp_attributes, a);
}

void SdpModifier::addMediaAttribute(sdp_media_t* mline, const char* name, const char* value) {
	sdp_attribute_t* a = (sdp_attribute_t*)su_alloc(mHome, sizeof(sdp_attribute_t));
	memset(a, 0, sizeof(*a));
	a->a_size = sizeof(*a);
	a->a_name = su_strdup(mHome, name);
	a->a_value = su_strdup(mHome, value);
	sdp_attribute_append(&mline->m_attributes, a);
}

int SdpModifier::update(msg_t* msg, sip_t* sip) {
	char buf[16384];
	int err = 0;
	char const* sdp;
	sdp_printer_t* printer = sdp_print(mHome, mSession, buf, sizeof(buf), 0);

	if (printer && (sdp = sdp_message(printer)) != NULL) {
		isize_t msgsize = sdp_message_size(printer);
		sip_payload_t* payload = sip_payload_make(mHome, sdp);
		err = sip_header_remove(msg, sip, (sip_header_t*)sip_payload(sip));
		if (err != 0) {
			LOGE("Could not remove payload from SIP message");
			goto end;
		}
		err = sip_header_insert(msg, sip, (sip_header_t*)payload);
		if (err != 0) {
			LOGE("Could not add payload to SIP message");
			goto end;
		}
		if (sip->sip_content_length != NULL) {
			sip_header_remove(msg, sip, (sip_header_t*)sip->sip_content_length);
			sip_header_insert(msg, sip, (sip_header_t*)sip_content_length_format(mHome, "%i", (int)msgsize));
		}
	} else {
		LOGE("Could not print SDP message !");
		err = -1;
	}
end:
	if (printer) sdp_printer_free(printer);
	return err;
}
