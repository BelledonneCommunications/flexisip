/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 4; tab-width: 4 -*- */
/*
 * bcproxy
 * Copyright (C) Simon Morlat 2010 <simon.morlat@linphone.org>
 * 
 * bcproxy is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * bcproxy is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <mediastreamer2/mscommon.h>
#include "common.hh"
#include <sofia-sip/sdp.h>
#include <sofia-sip/sip.h>

#ifndef _SDP_MODIFIER_HH_
#define _SDP_MODIFIER_HH_

class SdpModifier{
	public:
		static SdpModifier *createFromSipMsg(su_home_t *home, sip_t *sip);
		bool initFromSipMsg(sip_t *sip);
		void appendNewPayloads(const MSList *payloads);
		void changeAudioIpPort(const char *ip, int port);
		void update(msg_t *msg, sip_t *sip);
		~SdpModifier();
		SdpModifier(su_home_t *home);
	private:
		sip_t *mSip;
		su_home_t *mHome;
		sdp_session_t *mSession;
};

#endif // _SDP_MODIFIER_HH_
