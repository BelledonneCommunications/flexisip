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

#include "module.hh"
#include "agent.hh"
#include "registrardb.hh"
#include "log/logmanager.hh"

#include <sofia-sip/sip_status.h>
#include <fstream>
#include <csignal>
#include "lateforkapplier.hh"

using namespace ::std;

class ModuleRegistrar;
static ModuleRegistrar *sRegistrarInstanceForSigAction=NULL;

struct RegistrarStats {
	unique_ptr<StatPair> mCountBind;
	unique_ptr<StatPair> mCountClear;
	StatCounter64 *mCountLocalActives;
};

class ModuleRegistrar: public Module, public ModuleToolbox {
	friend class OnBindListener;
	RegistrarStats mStats;
	static void staticRoutesRereadTimerfunc(su_root_magic_t *magic, su_timer_t *t, void *data){
		ModuleRegistrar *r=(ModuleRegistrar *)data;
		r->readStaticRecords();
	}
public:
	void sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts=NULL);
	void routeRequest(shared_ptr<RequestSipEvent> &ev, Record *aorb, const url_t *sipUri);

	ModuleRegistrar(Agent *ag) : Module(ag),mStaticRecordsTimer(NULL) {
		sRegistrarInstanceForSigAction=this;
		memset(&mSigaction, 0, sizeof(mSigaction));
	}

	~ModuleRegistrar() {
	}

	virtual void onDeclare(GenericStruct *mc) {
		ConfigItemDescriptor configs[] = {
			{ StringList, "reg-domains", "List of whitelist separated domain names to be managed by the registrar.", "localhost" },
			{ Integer, "max-contacts-by-aor", "Maximum number of registered contacts of an address of record.", "15" },
			{ StringList, "unique-id-parameters", "List of contact uri parameters that can be used to identify a user's device. "
					"The contact parameters are searched in the order of the list, the first matching parameter is used and the others ignored.", "line" },
			{ Integer, "max-expires"	, "Maximum expire time for a REGISTER, in seconds.", "86400" },
			{ Integer, "min-expires"	, "Minimum expire time for a REGISTER, in seconds.", "60" },
			{ String, "static-records-file", "File containing the static records to add to database at startup. "
					"Format: one 'sip_uri contact_header' by line. Example:\n"
					"<sip:contact@domain> <sip:127.0.0.1:5460>,<sip:192.168.0.1:5160>", "" },
			{ Integer, "static-records-timeout", "Timeout in seconds after which the static records file is re-read and the contacts updated.", "600" },

			{ String , "db-implementation", "Implementation used for storing address of records contact uris. [redis-async, redis-sync, internal]","internal"},

			// Redis config support
			{ String , "redis-server-domain", "Domain of the redis server. ","localhost"},
			{ Integer , "redis-server-port", "Port of the redis server.","6379"},
			{ String , "redis-auth-password", "Authentication password for redis. Empty to disable.",""},
			{ Integer , "redis-server-timeout", "Timeout in milliseconds of the redis connection.","1500"},
			{ String , "redis-record-serializer", "Implementation of the contact serialiser to use. [C, protobuf]","protobuf"},
			config_item_end
		};
		mc->addChildrenValues(configs);

		mStats.mCountClear = mc->createStats("count-clear", "Number of cleared registrations.");
		mStats.mCountBind = mc->createStats("count-bind", "Number of registers.");
		mStats.mCountLocalActives = mc->createStat("count-local-registered-users", "Number of users currently registered through this server.");
	}

	virtual void onLoad(const GenericStruct *mc) {
		list<string>::const_iterator it;
		mDomains = mc->get<ConfigStringList>("reg-domains")->read();
		for (it = mDomains.begin(); it != mDomains.end(); ++it) {
			LOGD("Found registrar domain: %s", (*it).c_str());
		}
		mMaxExpires = mc->get<ConfigInt>("max-expires")->read();
		mMinExpires = mc->get<ConfigInt>("min-expires")->read();
		mStaticRecordsFile = mc->get<ConfigString>("static-records-file")->read();
		mStaticRecordsTimeout = mc->get<ConfigInt>("static-records-timeout")->read();
		
		if (!mStaticRecordsFile.empty()) {
			readStaticRecords(); // read static records from configuration file
			mStaticRecordsTimer=mAgent->createTimer(mStaticRecordsTimeout*1000, &staticRoutesRereadTimerfunc,this);
		}
		mSigaction.sa_sigaction = ModuleRegistrar::sighandler;
		mSigaction.sa_flags = SA_SIGINFO;
		sigaction(SIGUSR1, &mSigaction, NULL);
		sigaction(SIGUSR2, &mSigaction, NULL);
	}

	virtual void onUnload() {
		if (mStaticRecordsTimer) {
			su_timer_destroy(mStaticRecordsTimer);
		}
		Record::setStaticRecordsVersion(0);
	}

	// Delta from expires header, normalized with custom rules.
	unsigned int getMainDelta(sip_expires_t *expires) {
		unsigned int delta = mMaxExpires;
		if (expires) {
			delta = expires->ex_delta;
			if (delta < mMinExpires && delta > 0) {
				delta = mMinExpires;
			} else if (delta > mMaxExpires) {
				delta = mMaxExpires;
			}
		}
		return delta;
	}

	// Check star rules.
	// If *, it must be the only contact.
	// If *, associated expire must be 0.
	static bool checkStarUse(const sip_contact_t *contact, int expires) {
		bool starFound = false;
		int count = 0;
		do {
			if (starFound) {
				return false;
			}

			++count;
			if ('*' == contact->m_url[0].url_scheme[0]) {
				if (count > 1 || 0 != expires)
					return false;
				starFound = true;
			}
		} while (NULL != (contact = contact->m_next));
		return true;
	}

	virtual void onRequest(shared_ptr<RequestSipEvent> &ev);

	virtual void onResponse(shared_ptr<ResponseSipEvent> &ev);

	virtual void onTransactionEvent(shared_ptr<TransactionEvent> ev);

	void idle() { updateLocalRegExpire(); }

private:
	void updateLocalRegExpire() {
		RegistrarDb *db = RegistrarDb::get(mAgent);
		db->mLocalRegExpire->removeExpiredBefore(getCurrentTime());
		mStats.mCountLocalActives->set(db->mLocalRegExpire->countActives());
	}
	bool isManagedDomain(const url_t *url) {
		return ModuleToolbox::isManagedDomain(getAgent(), mDomains, url);
	}
	void readStaticRecords();
	bool contactUrlInVia(const url_t *ct_url, sip_via_t * via);
	list<string> mDomains;
	unsigned int mMaxExpires, mMinExpires;
	string mStaticRecordsFile;
	su_timer_t *mStaticRecordsTimer;
	int mStaticRecordsTimeout;
	struct sigaction mSigaction;
	static void sighandler(int signum, siginfo_t *info, void *ptr);

	static ModuleInfo<ModuleRegistrar> sInfo;
};

// Listener class NEED to copy the shared pointer
class OnStaticBindListener: public RegistrarDbListener {
	friend class ModuleRegistrar;
	Agent *agent;
	string line;
public:
	OnStaticBindListener(Agent *agent, const string& line) :
			agent(agent), line(line) {
	}
	void onRecordFound(Record *r) {
		LOGD("Static route added: %s", line.c_str());
	}
	void onError() {
		LOGE("Can't add static route: %s", line.c_str());
	}
};

void ModuleRegistrar::readStaticRecords() {
	static int version=0;
	if (mStaticRecordsFile.empty()) return;
	LOGD("Reading static records file");

	su_home_t home;

	stringstream ss;
	ss.exceptions(ifstream::failbit | ifstream::badbit);

	string line;
	string from;
	string contact_header;

	ifstream file;
	file.open(mStaticRecordsFile);
	if (file.is_open()) {
		su_home_init(&home);
		++version;
		const char *fakeCallId=su_sprintf(&home,"static-record-v%d",version);
		Record::setStaticRecordsVersion(version);
		while (file.good() && getline(file, line).good()) {
			size_t i;
			bool is_a_comment=false;
			for(i=0;i<line.size();++i){
				//skip spaces or comments
				if (isblank(line[i])) continue;
				if (line[i]=='#') is_a_comment=true;
				else break;
			}
			if (is_a_comment) continue;
			if (i==line.size()) continue; //blank line
			size_t cttpos = line.find_first_of(' ',i);
			if (cttpos != string::npos && cttpos < line.size()) {
				// Read uri
				from = line.substr(0, cttpos);

				// Read contacts
				contact_header = line.substr(cttpos+1, line.length() - cttpos+1);

				// Create
				sip_contact_t *url = sip_contact_make(&home, from.c_str());
				sip_contact_t *contact = sip_contact_make(&home, contact_header.c_str());
				int expire=mStaticRecordsTimeout+5; // 5s to avoid race conditions

				if (url != NULL && contact != NULL) {
					auto listener=make_shared<OnStaticBindListener>(getAgent(), line);
					bool alias=isManagedDomain(contact->m_url);
					RegistrarDb::get(mAgent)->bind(url->m_url, contact, fakeCallId, version, NULL, expire, alias, listener);
					continue;
				}
			}
			LOGW("Incorrect line format: %s", line.c_str());
		}
		su_home_deinit(&home);
	} else {
		LOGE("Can't open file %s", mStaticRecordsFile.c_str());
	}

}

void ModuleRegistrar::sendReply(shared_ptr<RequestSipEvent> &ev, int code, const char *reason, const sip_contact_t *contacts) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip=ms->getSip();
	
	if (sip->sip_request->rq_method==sip_method_invite){
		shared_ptr<CallLog> clog=ev->getEventLog<CallLog>();
		if (clog){
			clog->setStatusCode(code,reason);
			clog->setCompleted();
		}
	}else if (sip->sip_request->rq_method==sip_method_message){
		shared_ptr<MessageLog> mlog=ev->getEventLog<MessageLog>();
		if (mlog){
			mlog->setStatusCode(code,reason);
			mlog->setCompleted();
		}
	}
	if (contacts != NULL) {
		ev->reply(code, reason, SIPTAG_CONTACT(contacts), SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		ev->reply(code, reason, SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

/**
 * Check if the contact is in one via.
 * Avoid to check a contact information that already known
 */
bool ModuleRegistrar::contactUrlInVia(const url_t *url, sip_via_t * via) {

	while (via != NULL) {
		if (via->v_host && url->url_host && !strcmp(via->v_host, url->url_host)) {
			const char *port1 = (via->v_port) ? via->v_port : "5060";
			const char *port2 = (url->url_port) ? url->url_port : "5060";
			if (!strcmp(port1, port2))
				return true;
		}
		via = via->v_next;
	}

	return false;
}



// Listener class NEED to copy the shared pointer
class OnBindListener: public RegistrarDbListener {
	ModuleRegistrar *mModule;
	shared_ptr<RequestSipEvent> mEv;
	sip_from_t * mSipFrom;
	su_home_t mHome;
	sip_contact_t *mContact;
public:
	OnBindListener(ModuleRegistrar *module, shared_ptr<RequestSipEvent> ev, const sip_from_t* sipuri = NULL, sip_contact_t *contact = NULL) :
			mModule(module), mEv(ev), mSipFrom(NULL), mContact(NULL) {
		ev->suspendProcessing();
		su_home_init(&mHome);
		if (contact)
			mContact = sip_contact_copy(&mHome, contact);
		if (sipuri){
			mSipFrom=sip_from_dup(&mHome,sipuri);
		}
	}
	~OnBindListener() {
		su_home_deinit(&mHome);
	}

	inline void eventLogRecordFound() {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		
		RegistrationLog::Type type;
		if (ms->getSip()->sip_expires && ms->getSip()->sip_expires->ex_delta==0)
			type=RegistrationLog::Unregister; //REVISIT not 100% exact.
		else
			type=RegistrationLog::Register;

		string id(mContact ? Record::extractUniqueId(mContact) : "");
		auto evlog=make_shared<RegistrationLog>(type,ms->getSip()->sip_from,id, mContact);

		if (ms->getSip()->sip_user_agent)
			evlog->setUserAgent(ms->getSip()->sip_user_agent);

		evlog->setCompleted();
		mEv->setEventLog(evlog);
	}

	void onRecordFound(Record *r) {
		const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
		time_t now = getCurrentTime();
		if (r){
			mModule->sendReply(mEv, 200, "Registration successful", r->getContacts(ms->getHome(), now));
			LateForkApplier::onContactRegistered(mModule->getAgent(), mEv, mContact, r, mSipFrom->a_url);
			eventLogRecordFound();
		}else{
			LOGE("OnBindListener::onRecordFound(): Record is null");
			mModule->sendReply(mEv,SIP_480_TEMPORARILY_UNAVAILABLE);
		}
	}
	void onError() {
		mModule->sendReply(mEv, SIP_500_INTERNAL_SERVER_ERROR);
	}
};

class FakeFetchListener: public RegistrarDbListener {
	friend class ModuleRegistrar;
public:
	FakeFetchListener() {
	}
	void onRecordFound(Record *r) {
		if (r!=NULL) {
			SLOGD << r;
		} else {
			LOGD("No record found");
		}
	}
	void onError() {
	}
};


void ModuleRegistrar::sighandler(int signum, siginfo_t* info, void* ptr) {
	if (signum == SIGUSR1) {
		LOGI("Received signal triggering static records file re-read");
		sRegistrarInstanceForSigAction->readStaticRecords();
	} else if (signum == SIGUSR2) {
		LOGI("Received signal triggering fake fetch");
		su_home_t home;
		su_home_init(&home);
		url_t *url=url_make(&home, "sip:contact@domain");
		
		auto listener=make_shared<FakeFetchListener>();
		RegistrarDb::get(sRegistrarInstanceForSigAction->getAgent())->fetch(url, listener, false);
	}
}


void ModuleRegistrar::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();

	if (sip->sip_request->rq_method != sip_method_register) return;
	
	url_t *sipurl = sip->sip_from->a_url;
	if (!sipurl->url_host || !isManagedDomain(sipurl)) return;
	
	sip_expires_t *expires = sip->sip_expires;
	int maindelta = getMainDelta(expires);
	if (sip->sip_contact != NULL) {
		if (!checkStarUse(sip->sip_contact, maindelta)) {
			LOGD("The star rules are not respected.");
			sendReply(ev,400, "Invalid Request");
			return;
		}
		if ('*' == sip->sip_contact->m_url[0].url_scheme[0]) {
			auto listener = make_shared<OnBindListener>(this, ev);
			mStats.mCountClear->incrStart();
			LOGD("Clearing bindings");
			listener->addStatCounter(mStats.mCountClear->finish);
			RegistrarDb::get(mAgent)->clear(sip, listener);
			return;
		} else {
			auto listener = make_shared<OnBindListener>(this, ev, sip->sip_from, sip->sip_contact);
			mStats.mCountBind->incrStart();
			LOGD("Updating binding");
			listener->addStatCounter(mStats.mCountBind->finish);
			RegistrarDb::get(mAgent)->bind(sip, mAgent->getPreferredRoute().c_str(), maindelta, false, listener);
			return;
		}
		LOGD("Records binded to registrar database.");
	} else {
		LOGD("No sip contact, it is a fetch only request for %s.", url_as_string(ms->getHome(), sipurl));
		RegistrarDb::get(mAgent)->fetch(sipurl, make_shared<OnBindListener>(this, ev));
		return;
	}
}



void ModuleRegistrar::onResponse(shared_ptr<ResponseSipEvent> &ev) {
}

void ModuleRegistrar::onTransactionEvent(shared_ptr<TransactionEvent> ev) {
}

ModuleInfo<ModuleRegistrar> ModuleRegistrar::sInfo("Registrar",
		"The ModuleRegistrar module accepts REGISTERs for domains it manages, and store the address of record "
		"in order to allow routing requests destinated to the client who registered.",
		ModuleInfoBase::ModuleOid::Registrar);

