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
#include <sofia-sip/su_wait.h>

#include "common.hh"
#include "configmanager.hh"

#include <list>

class DomainRegistrationManager;
class Agent;

class DomainRegistration {
  public:
	DomainRegistration(DomainRegistrationManager &mgr, const std::string &localDomain, const url_t *parent_proxy,
					   const std::string &clientCertdir, const std::string &passphrase, int lineIndex);
	void start();
	void stop();
	bool isUs(const url_t *url);
	bool hasTport(const tport_t *tport) const;
	const url_t *getPublicUri() const;
	~DomainRegistration();

  private:
	struct uuid_t {
		unsigned int time_low;
		unsigned short time_mid;
		unsigned short time_hi_and_version;
		unsigned char clock_seq_hi_and_reserved;
		unsigned char clock_seq_low;
		unsigned char node[6];
	};

	void setContact(msg_t *msg);
	int getExpires(nta_outgoing_t *orq, const sip_t *response);
	static void sOnConnectionBroken(tp_stack_t *stack, tp_client_t *client, tport_t *tport, msg_t *msg, int error);
	static int sLegCallback(nta_leg_magic_t *ctx, nta_leg_t *leg, nta_incoming_t *incoming, const sip_t *request);
	static int sResponseCallback(nta_outgoing_magic_t *ctx, nta_outgoing_t *orq, const sip_t *resp);
	static void sRefreshRegistration(su_root_magic_t *magic, su_timer_t *timer, su_timer_arg_t *arg);
	void responseCallback(nta_outgoing_t *orq, const sip_t *resp);
	void onConnectionBroken(tport_t *tport, msg_t *msg, int error);
	void cleanCurrentTport();
	int generateUuid(const std::string &uniqueId);
	DomainRegistrationManager &mManager;
	StatCounter64 * mRegistrationStatus; //This contains the lastest SIP response code of the REGISTER transaction.
	su_home_t mHome;
	nta_leg_t *mLeg;
	tport_t *mPrimaryTport; // the tport that has the configuration
	tport_t *mCurrentTport; // the secondary tport that has the active connection.
	int mPendId;
	su_timer_t *mTimer;
	url_t *mFrom;
	url_t *mProxy;
	sip_contact_t *mExternalContact;
	std::string mUuid;
};

class DomainRegistrationManager {
	friend class DomainRegistration;

  public:
	DomainRegistrationManager(Agent *agent);
	int load(std::string passphrase);
	/**
	 * check is url is a local contact of any existing domain registration.
	 */
	bool isUs(const url_t *url) const;
	/**
	 * If this tport was created as result of domain registration, returns the known public ip/port.
	 * This is useful for setting correct Record-Routes for request arriving through these connections.
	**/
	const url_t *getPublicUri(const tport_t *tport) const;
	~DomainRegistrationManager();

  private:
	Agent *mAgent;
	std::list<std::shared_ptr<DomainRegistration>> mRegistrations;
	GenericStruct *mDomainRegistrationArea; /*this is used to place statistics values*/
	int mKeepaliveInterval;
	bool mVerifyServerCerts;
};

#endif
