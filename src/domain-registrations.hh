/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

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


#ifndef domainregistrations_hh
#define domainregistrations_hh



#include <sofia-sip/msg.h>
#include <sofia-sip/nta.h>
#include <sofia-sip/tport.h>

#include "common.hh"
#include "configmanager.hh"

#include <list>

class DomainRegistrationManager;

class DomainRegistration{
public:
	DomainRegistration(DomainRegistrationManager &mgr, const std::string &localDomain, const url_t *parent_proxy, const std::string &clientCertdir);
	void start();
	void stop();
	~DomainRegistration();
private:
	void setContact(msg_t *msg);
	static int legCallback(nta_leg_magic_t *ctx, nta_leg_t *leg, nta_incoming_t *incoming, const sip_t *request);
	static int responseCallback(nta_outgoing_magic_t *ctx, nta_outgoing_t *orq, const sip_t *resp);
	DomainRegistrationManager &mManager;
	su_home_t mHome;
	nta_leg_t *mLeg;
	tport_t *mTport;
	su_timer_t *mTimer;
	url_t *mFrom;
	url_t *mProxy;
};

class DomainRegistrationManager{
friend class DomainRegistration;
public:
	DomainRegistrationManager(nta_agent_t *agent);
	int load(const std::string &configFile);
	~DomainRegistrationManager();
private:
	nta_agent_t *mAgent;
	
	std::list<std::shared_ptr<DomainRegistration>> mRegistrations;
};


#endif
