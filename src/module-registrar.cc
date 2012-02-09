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

#include "agent.hh"
#include "registrardb.hh"

using namespace::std;



class Registrar : public Module, public ModuleToolbox {
public:
		static void send480KO(Agent *agent, std::shared_ptr<SipEvent> &ev);
		static void send200Ok(Agent *agent, std::shared_ptr<SipEvent> &ev, const sip_contact_t *contacts);
		void routeRequest(Agent *agent, std::shared_ptr<SipEvent> &ev, Record *aor);

		Registrar(Agent *ag) : Module(ag){
		}

		virtual void onDeclare(ConfigStruct *module_config){
			ConfigItemDescriptor items[]={
				{	StringList	,	"reg-domains",	"List of whitelist separated domain names to be managed by the registrar.","localhost"},
				{	Integer		,	"max-contacts-by-aor",	"Maximum number of registered contacts of an address of record.","15"},
				{	String		,	"line-field-name",	"Name of the contact uri parameter used for identifying user's device. ","line"},

#ifdef ENABLE_REDIS
				{	String		,	"db-implementation",	"Implementation used for storing address of records contact uris. [redis-async, redis-sync, internal]","redis-async"},
				{	String		,	"redis-server-domain",	"Domain of the redis server. ","localhost"},
				{	Integer		,	"redis-server-port",	"Port of the redis server.","6379"},
				{	String		,	"redis-auth-password",	"Authentication password for redis. Empty to disable.",""},
				{	Integer		,	"redis-server-timeout",	"Timeout in milliseconds of the redis connection.","1500"},
				{	String		,	"redis-record-serializer",	"Implementation of the contact serialiser to use. [C, protobuf]","protobuf"},
#else
				{	String		,	"db-implementation",	"Implementation used for storing address of records contact uris. [internal,...]","internal"},
#endif
				config_item_end
			};
			module_config->addChildrenValues(items);
		}
		
		virtual void onLoad(Agent *agent, const ConfigStruct *module_config){
			list<string>::const_iterator it;
			mDomains=module_config->get<ConfigStringList>("reg-domains")->read();
			for (it=mDomains.begin();it!=mDomains.end();++it){
				LOGD("Found registrar domain: %s",(*it).c_str());
			}
		}


		// Delta from expires header, normalized with custom rules.
		static int getMainDelta(sip_expires_t *expires){
			int delta=3600;
			if (expires){
				delta=expires->ex_delta;
				if (delta<30){
					delta=30;
				}
				if (delta > 3600*24)
					delta=3600*24;
			}
			return delta;
		}

		// Check star rules.
		// If *, it must be the only contact.
		// If *, associated expire must be 0.
		static bool checkStarUse(const sip_contact_t *contact, int expires){
			bool starFound=false;
			int count=0;
			do {
				if (starFound){
					return false;
				}

				++count;
				if ('*' == contact->m_url->url_scheme[0]){
					if (count > 1 || 0 !=expires)
						return false;
					starFound=true;
				}
			} while (NULL != (contact=contact->m_next));
			return true;
		}

		virtual void onRequest(std::shared_ptr<SipEvent> &ev);

		virtual void onResponse(std::shared_ptr<SipEvent> &ev){
		}

	private:
		bool isManagedDomain(const char *domain){
			return ModuleToolbox::matchesOneOf(domain,mDomains);
		}
		list<string> mDomains;
		static ModuleInfo<Registrar> sInfo;
};


void Registrar::send480KO(Agent *agent, std::shared_ptr<SipEvent> &ev){
	nta_msg_treply(agent->getSofiaAgent (),ev->mMsg,480,
			"Temporarily Unavailable",
			SIPTAG_SERVER_STR(agent->getServerString()),
			TAG_END());
	ev->stopProcessing();
}

void Registrar::send200Ok(Agent *agent, std::shared_ptr<SipEvent> &ev, const sip_contact_t *contacts){
	if (contacts != NULL){
		nta_msg_treply(agent->getSofiaAgent (),ev->mMsg,200,"Registration successful",
				SIPTAG_CONTACT(contacts),
				SIPTAG_SERVER_STR(agent->getServerString()),
				TAG_END());
	} else {
		nta_msg_treply(agent->getSofiaAgent (),ev->mMsg,200,"Registration successful",
				SIPTAG_SERVER_STR(agent->getServerString()),
				TAG_END());
	}
}

static extended_contact *getFirstExtendedContact(Record *aor) {
	const list<extended_contact*> contacts=aor->getExtendedContacts();
	list<extended_contact*>::const_iterator it=contacts.begin();
	return it != contacts.end() ? (*it) : NULL;
}

void Registrar::routeRequest(Agent *agent, std::shared_ptr<SipEvent> &ev, Record *aor){
	// here we would implement forking
	time_t now=time(NULL);
	extended_contact *ec=aor?getFirstExtendedContact(aor):NULL;
	sip_contact_t *ct=NULL;
	if (ec) ct=Record::extendedContactToSofia(ev->getHome(), ec, now);

	/*sanity check on the contact address: might be '*' or whatever useless information*/
	if (ct && ct->m_url->url_host!=NULL && ct->m_url->url_host[0]!='\0'){
		LOGD("Registrar: found contact information in database, rewriting request uri");
		/*rewrite request-uri */
		ev->mSip->sip_request->rq_url[0]=*url_hdup(ev->getHome(),ct->m_url);
		if (0!=strcmp(agent->getPreferredRoute().c_str(),ec->mRoute)) {
			LOGD("This flexisip instance is not responsible for contact %s -> %s",
					ec->mSipUri, ec->mRoute);
			prependRoute(ev->getHome(),agent,ev->mMsg,ev->mSip, ec->mRoute);
		}
		// Back to work
		agent->injectRequestEvent(ev);
	}else{
		if (ct!=NULL){
			LOGW("Unrouted request because of incorrect address of record.");
		}

		LOGD("This user isn't registered.");
		nta_msg_treply(agent->getSofiaAgent (),ev->mMsg,404,"User not found",
				SIPTAG_SERVER_STR(agent->getServerString()),
		       TAG_END());
		ev->stopProcessing();
	}
}

// Listener class NEED to copy the shared pointer
class OnBindListener : public RegistrarDbListener {
	friend class Registrar;
	Agent *agent;
	std::shared_ptr<SipEvent> ev;
public:
	OnBindListener(Agent *agent,std::shared_ptr<SipEvent> ev) : agent(agent),ev(ev){
		ev->stopProcessing();
	};
	void onRecordFound(Record *r){
		time_t now=time(NULL);
		Registrar::send200Ok(agent, ev, r->getContacts(ev->getHome(), now));
		delete this;
	}
	void onError(){
		Registrar::send480KO(agent, ev);
		delete this;
	}
};

// Listener class NEED to copy the shared pointer
class OnBindForRoutingListener : public RegistrarDbListener {
	friend class Registrar;
	Registrar *mModule;
	Agent *mAgent;
	std::shared_ptr<SipEvent> mEv;
public:
	OnBindForRoutingListener(Registrar *module, Agent *agent,std::shared_ptr<SipEvent> ev) : mModule(module),mAgent(agent),mEv(ev){
		ev->stopProcessing();
	};
	void onRecordFound(Record *r){
		mModule->routeRequest(mAgent, mEv, r);
		delete this;
	}
	void onError(){
		Registrar::send480KO(mAgent, mEv);
		delete this;
	}
};


void Registrar::onRequest(shared_ptr<SipEvent> &ev){
	sip_t *sip=ev->mSip;
	if (sip->sip_request->rq_method==sip_method_register){
		url_t *sipurl=sip->sip_from->a_url;
		if (sipurl->url_host && isManagedDomain(sipurl->url_host)){
			sip_expires_t *expires=sip->sip_expires;
			int maindelta=getMainDelta(expires);
			if (sip->sip_contact != NULL){
				if (!checkStarUse(sip->sip_contact, maindelta)){
					LOGD("The star rules are not respected.");
					nta_msg_treply(getAgent()->getSofiaAgent (),ev->mMsg,400,
							"Invalid Request",
							SIPTAG_SERVER_STR(getAgent()->getServerString()),
							TAG_END());
					ev->stopProcessing();
					return;
				}
				if ('*' == sip->sip_contact->m_url->url_scheme[0]){
					OnBindListener *listener=new OnBindListener(getAgent(),ev);
					LOGD("Clearing bindings");
					RegistrarDb::get(mAgent)->clear(sip, listener);
					return;
				} else {
					OnBindListener *listener=new OnBindListener(getAgent(),ev);
					LOGD("Updating binding");
					RegistrarDb::get(mAgent)->bind(sip, mAgent->getPreferredRoute().c_str(), maindelta, listener);
					return;
				}
				LOGD("Records binded to registrar database.");
			} else {
				OnBindListener *listener=new OnBindListener(getAgent(),ev);
				LOGD("No sip contact, it is a fetch only.");
				RegistrarDb::get(mAgent)->fetch(sipurl, listener);
				return;
			}

			/*we need to answer directly */

			ev->stopProcessing();
		}
	}else{
		/*see if we can route other requests */
		/*acks shall not have their request uri rewritten:
			- they can be for us (in response to a 407 for invite)
			- they can be for the a remote peer, in which case they will have the correct contact address in the request uri
		*/
		if (sip->sip_request->rq_method!=sip_method_ack){
			url_t *sipurl=sip->sip_request->rq_url;
			if (sipurl->url_host && isManagedDomain(sipurl->url_host)){
				RegistrarDbListener *listener=new OnBindForRoutingListener(this,getAgent(),ev);
				RegistrarDb::get(mAgent)->fetch(sipurl, listener);
			}
		}
	}
}

ModuleInfo<Registrar> Registrar::sInfo("Registrar",
	"The Registrar module accepts REGISTERs for domains it manages, and store the address of record "
    "in order to route other requests destinated to the client who registered.");

