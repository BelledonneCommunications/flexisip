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


#ifndef callstore_hh
#define callstore_hh

#include "agent.hh"
#include <list>

class CallContextBase{
	public:
		CallContextBase(sip_t *sip);
		bool match(sip_t *sip);
		bool isNewInvite(sip_t *sip);
		void storeNewInvite(msg_t *orig);
		bool isNew200Ok(sip_t *sip);
		void storeNewResponse(msg_t *msg);
		msg_t *getLastForwardedInvite()const;
		msg_t *getLastForwaredResponse()const;
		virtual void dump();
		virtual bool isInactive(time_t cur){
			return false;
		}
		su_home_t *getHome(){
			return &mHome;
		}
		virtual ~CallContextBase();
	private:
		su_home_t mHome;
		msg_t *mInvite;
		msg_t *mResponse;
		uint32_t mCallHash;
		uint32_t mInvCseq;
		uint32_t mResCseq;
};

class CallStore{
	public:
		CallStore();
		void store(CallContextBase *ctx);
		CallContextBase *find(sip_t *sip);
		void remove(CallContextBase *ctx);
		void removeInactives();
		void dump();
	private:
		std::list<CallContextBase*> mCalls;
};


#endif
