/*
	Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010  Belledonne Communications SARL.

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

#include "common.hh"
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip.h>
#include <functional>
#include <string>
#include <list>

#ifndef _SDP_MODIFIER_HH_
#define _SDP_MODIFIER_HH_


#define payload_type_set_number(pt,n)	(pt)->user_data=(void*)(long)n
#define payload_type_get_number(pt)		(int)(long)(pt)->user_data

struct _PayloadType;
typedef struct _PayloadType PayloadType;

/**
 * Utility class used to do various changes in an existing SDP message.
**/
class SdpModifier{
	public:
		static SdpModifier *createFromSipMsg(su_home_t *home, sip_t *sip, const std::string &nortproxy = "");
		static bool hasSdp(const sip_t *sip);
		bool initFromSipMsg(sip_t *sip);
		#if ENABLE_TRANSCODER
		std::list<PayloadType *> readPayloads();
		void replacePayloads(const std::list<PayloadType *> &payloads, const std::list<PayloadType *> &preserved_numbers);
		static std::list<PayloadType *> findCommon(const std::list<PayloadType *> &offer, const std::list<PayloadType *> &answer, bool use_offer_numbering);
		#endif
		int readPtime();
		short getAudioIpVersion();
		void getAudioIpPort(std::string *ip, int *port);
		void changeAudioIpPort(const char *ip, int port);
		void changeMediaConnection(sdp_media_t *mline, const char *relay_ip);
		void addIceCandidate(std::function<void(int, std::string *, int *)>, std::function<void(int, std::string *, int*)>);
		void iterate(std::function<void(int, const std::string &, int)>);
		void masquerade(std::function<void(int, std::string *, int *)>);
		void addAttribute(const char *name, const char *value);
		bool hasAttribute(const char *name);
		void addMediaAttribute(sdp_media_t *mline, const char *name, const char *value);
		bool hasMediaAttribute(sdp_media_t *mline, const char *name);
		bool hasIceCandidate(sdp_media_t *mline, const std::string &addr, int port);
		void update(msg_t *msg, sip_t *sip);
		void setPtime(int ptime);
		virtual ~SdpModifier();
		SdpModifier(su_home_t *home, std::string nortproxy);
		sdp_session_t *mSession;
		sip_t *mSip;
	private:
		sdp_parser_t *mParser;
		su_home_t *mHome;
		std::string mNortproxy;
};

#endif // _SDP_MODIFIER_HH_
