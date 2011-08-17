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

#include <mediastreamer2/mscommon.h>
#include "common.hh"
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip.h>

#include <string>

#ifndef _SDP_MODIFIER_HH_
#define _SDP_MODIFIER_HH_


#define payload_type_set_number(pt,n)	(pt)->user_data=(void*)(long)n
#define payload_type_get_number(pt)		(int)(long)(pt)->user_data

class Masquerader{
	public:
		virtual void onNewMedia(int mline, std::string *ip, int *port, const char* tag)=0;
};

/**
 * Utility class used to do various changes in an existing SDP message.
**/
class SdpModifier{
	public:
		static SdpModifier *createFromSipMsg(su_home_t *home, sip_t *sip);
		bool initFromSipMsg(sip_t *sip);
		MSList *readPayloads();
		void replacePayloads(const MSList *payloads, const MSList *preserved_numbers);
		void getAudioIpPort(std::string *ip, int *port);
		void changeAudioIpPort(const char *ip, int port);
		void changeIpPort(Masquerader *m, const char *partytag);
		void update(msg_t *msg, sip_t *sip);
		~SdpModifier();
		SdpModifier(su_home_t *home);
		static MSList *findCommon(const MSList *offer, const MSList *answer, bool use_offer_numbering);
	private:
		sdp_parser_t *mParser;
		sip_t *mSip;
		su_home_t *mHome;
		sdp_session_t *mSession;
};

#endif // _SDP_MODIFIER_HH_
