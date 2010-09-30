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


#ifndef agent_hh
#define agent_hh


#include <string>

#include <sofia-sip/sip.h>
#include <sofia-sip/sip_protos.h>
#include <sofia-sip/sip_util.h>
#include <sofia-sip/sip_tag.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/nta_stateless.h>
#include <sofia-sip/msg.h>

#include "common.hh"
#include "configmanager.hh"
#include "module.hh"

class Transaction{
	public:
		Transaction(sip_t *request);
		~Transaction();
		bool matches(sip_t *sip);
		void setUserPointer(void *up);
		void *getUserPointer()const;
		su_home_t *getHome(){
			return &mHome;
		}
	private:
		su_home_t mHome;
		sip_from_t *mFrom;
		sip_from_t *mTo;
		sip_cseq_t *mCseq;
		void *mUser;
};

class Agent{
	public:
		Agent(su_root_t *root, const char *locaddr, int port);
		virtual void loadConfig(ConfigManager *cm);
		void setDomain(const std::string &domain);
		virtual ~Agent();
		const std::string getLocAddr()const{
			return mLocAddr;
		}
		int getPort()const{
			return mPort;
		}
		void idle();
		bool isUs(const url_t *url)const;
		nta_agent_t* getSofiaAgent()const{
			return mAgent;
		}
	protected:
		int onIncomingMessage(msg_t *msg, sip_t *sip);
		void onRequest(msg_t *msg, sip_t *sip);
		void onResponse(msg_t *msg, sip_t *sip);
	private:
		std::list<Module*> mModules;
		std::list<std::string> mAliases;
		std::string mLocAddr;
		std::string mDomain;
		int mPort;
		nta_agent_t *mAgent;
		static int messageCallback(nta_agent_magic_t *context, nta_agent_t *agent,msg_t *msg,sip_t *sip);
};

#endif

