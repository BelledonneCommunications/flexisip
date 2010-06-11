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

#ifndef transcodeagent_hh
#define transcodeagent_hh

#include "agent.hh"
#include "callcontext.hh"

class TranscodeAgent : public Agent{
	public:
		TranscodeAgent(su_root_t *root, const char *locaddr, int port);
		~TranscodeAgent();
		virtual int onRequest(msg_t *msg, sip_t *sip);
		virtual int onResponse(msg_t *msg, sip_t *sip);
	private:
		void processNewInvite(CallContext *c, msg_t *msg, sip_t *sip);
		void process200OkforInvite(CallContext *ctx, msg_t *msg, sip_t *sip);
		MSList *mSupportedAudioPayloads;
		MSTicker *mTicker;
		CallStore mCalls;
};

#endif
