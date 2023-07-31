/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "registrar-db.hh"

#include <memory>

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"

#include "extended-contact.hh"
#include "record.hh"
#include "registrardb-internal.hh"
#include "registrardb-redis.hh"
#include "utils/uri-utils.hh"

using namespace std;

namespace flexisip {
using namespace redis::auth;

RegistrarDb::LocalRegExpire::LocalRegExpire(Agent* ag) : mAgent(ag) {
}

RegistrarDb::RegistrarDb(Agent* ag) : mLocalRegExpire(new LocalRegExpire(ag)), mAgent(ag), mUseGlobalDomain(false) {
	GenericStruct* cr = GenericManager::get()->getRoot();
	GenericStruct* mr = cr->get<GenericStruct>("module::Registrar");
	mGruuEnabled = mr->get<ConfigBoolean>("enable-gruu")->read();
}

RegistrarDb::~RegistrarDb() {
	delete mLocalRegExpire;
}

void RegistrarDb::addStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	auto it = find(mStateListeners.cbegin(), mStateListeners.cend(), listener);
	if (it == mStateListeners.cend()) mStateListeners.push_back(listener);
}

void RegistrarDb::removeStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	mStateListeners.remove(listener);
}

void RegistrarDb::notifyStateListener() const {
	for (auto& listener : mStateListeners)
		listener->onRegistrarDbWritable(mWritable);
}

void RegistrarDb::subscribe(const SipUri& url, std::weak_ptr<ContactRegisteredListener>&& listener) {
	this->subscribe(Record::defineKeyFromUrl(url.get()), std::move(listener));
}

bool RegistrarDb::subscribe(const string& topic, std::weak_ptr<ContactRegisteredListener>&& listener) {
	const auto& alreadyRegisteredListener = mContactListenersMap.equal_range(topic);

	const auto strongPtr = listener.lock();
	const auto listenerAlreadyPresent =
	    find_if(alreadyRegisteredListener.first, alreadyRegisteredListener.second, [&strongPtr](const auto& mapEntry) {
		    return mapEntry.second.lock() == strongPtr;
	    }) != alreadyRegisteredListener.second;
	if (listenerAlreadyPresent) {
		LOGD("Already subscribe topic = %s with listener %p", topic.c_str(), strongPtr.get());
		return false;
	}

	LOGD("Subscribe topic = %s with listener %p", topic.c_str(), strongPtr.get());
	mContactListenersMap.emplace(topic, std::move(listener));

	return true;
}

void RegistrarDb::unsubscribe(const string& topic, const shared_ptr<ContactRegisteredListener>& listener) {
	LOGD("Unsubscribe topic = %s with listener %p", topic.c_str(), listener.get());
	bool found = false;
	auto range = mContactListenersMap.equal_range(topic);
	for (auto it = range.first; it != range.second;) {
		if (it->second.lock() == listener) {
			found = true;
			it = mContactListenersMap.erase(it);
		} else it++;
	}
	if (!found) {
		LOGE("RegistrarDb::unsubscribe() for topic %s and listener = %p is invalid.", topic.c_str(), listener.get());
	}
}

class ContactNotificationListener : public ContactUpdateListener,
                                    public std::enable_shared_from_this<ContactNotificationListener> {
public:
	ContactNotificationListener(const string& uid, RegistrarDb* db, const SipUri& aor) : mUid(uid), mDb(db), mAor(aor) {
	}

private:
	// ContactUpdateListener implementation
	void onRecordFound(const shared_ptr<Record>& r) override {
		auto record = r ?: make_shared<Record>(mAor);
		mDb->notifyContactListener(record, mUid);
	}
	void onError() override {
	}
	void onInvalid() override {
	}
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
	}

	string mUid;
	RegistrarDb* mDb = nullptr;
	SipUri mAor;
};

void RegistrarDb::notifyContactListener(const string& key, const string& uid) {
	auto sipUri = Record::makeUrlFromKey(key);
	auto listener = make_shared<ContactNotificationListener>(uid, this, sipUri);
	LOGD("Notify topic = %s, uid = %s", key.c_str(), uid.c_str());
	RegistrarDb::get()->fetch(sipUri, listener, true);
}

void RegistrarDb::notifyContactListener(const shared_ptr<Record>& r, const string& uid) {
	auto range = mContactListenersMap.equal_range(r->getKey());

	/* Because invoking the listener might indirectly unregister listeners from the RegistrarDb, it is required
	 * to first create a local copy of the list of listeners we are going to invoke. */
	vector<shared_ptr<ContactRegisteredListener>> listeners{};
	for (auto it = range.first; it != range.second;) {
		if (auto strongPtr = it->second.lock()) {
			listeners.emplace_back(std::move(strongPtr));
			it++;
		} else {
			// Clear expired listener
			it = mContactListenersMap.erase(it);
		}
	}
	for (const auto& l : listeners) {
		LOGD("Notify topic = %s to listener %p", r->getKey().c_str(), l.get());
		l->onContactRegistered(r, uid);
	}
}

void RegistrarDb::LocalRegExpire::update(const shared_ptr<Record>& record) {
	unique_lock<mutex> lock(mMutex);
	time_t latest = record->latestExpire(mAgent);
	if (latest > 0) {
		auto it = mRegMap.find(record->getKey());
		if (it != mRegMap.end()) {
			(*it).second = latest;
		} else {
			if (!record->isEmpty() && !record->haveOnlyStaticContacts()) {
				mRegMap.insert(make_pair(record->getKey(), latest));
				notifyLocalRegExpireListener(mRegMap.size());
			}
		}
	} else {
		mRegMap.erase(record->getKey());
		notifyLocalRegExpireListener(mRegMap.size());
	}
}

size_t RegistrarDb::LocalRegExpire::countActives() {
	return mRegMap.size();
}
void RegistrarDb::LocalRegExpire::removeExpiredBefore(time_t before) {
	unique_lock<mutex> lock(mMutex);

	for (auto it = mRegMap.begin(); it != mRegMap.end();) {
		// LOGE("> %s [%lu]", (*it).first.c_str(), (*it).second-before);
		if ((*it).second <= before) {
			auto prevIt = it;
			++it;
			mRegMap.erase(prevIt);
			notifyLocalRegExpireListener(mRegMap.size());
		} else {
			++it;
		}
	}
}

void RegistrarDb::LocalRegExpire::getRegisteredAors(std::list<std::string>& aors) const {
	unique_lock<mutex> lock(mMutex);
	for (auto& pair : mRegMap) {
		aors.push_back(pair.first);
	}
}

void RegistrarDb::LocalRegExpire::subscribe(LocalRegExpireListener* listener) {
	LOGD("Subscribe LocalRegExpire");
	mLocalRegListenerList.push_back(listener);
}

void RegistrarDb::LocalRegExpire::unsubscribe(LocalRegExpireListener* listener) {
	LOGD("Unsubscribe LocalRegExpire");
	auto result = find(mLocalRegListenerList.begin(), mLocalRegListenerList.end(), listener);
	if (result != mLocalRegListenerList.end()) {
		mLocalRegListenerList.erase(result);
	}
}

void RegistrarDb::LocalRegExpire::notifyLocalRegExpireListener(unsigned int count) {
	LOGD("Notify LocalRegExpire count = %d", count);
	for (auto listener : mLocalRegListenerList) {
		listener->onLocalRegExpireUpdated(count);
	}
}

int RegistrarDb::countSipContacts(const sip_contact_t* contact) {
	int count = 0;
	sip_contact_t* current = (sip_contact_t*)contact;
	while (current) {
		if (!current->m_expires || atoi(current->m_expires) != 0) {
			++count;
		}
		current = current->m_next;
	}
	return count;
}

bool RegistrarDb::errorOnTooMuchContactInBind(const sip_contact_t* sip_contact,
                                              const string& key,
                                              [[maybe_unused]] const shared_ptr<RegistrarDbListener>& listener) {
	int nb_contact = this->countSipContacts(sip_contact);
	int max_contact = Record::getMaxContacts();
	if (nb_contact > max_contact) {
		LOGD("Too many contacts in register %s %i > %i", key.c_str(), nb_contact, max_contact);
		return true;
	}

	return false;
}

unique_ptr<RegistrarDb> RegistrarDb::sUnique = nullptr;

void RegistrarDb::resetDB() {
	SLOGW << "Reseting RegistrarDb static pointer, you MUST be in a test.";
	sUnique = nullptr;
}

RegistrarDb* RegistrarDb::initialize(Agent* ag) {
	if (sUnique != nullptr) {
		LOGF("RegistrarDb already initialized");
	}
	GenericStruct* cr = GenericManager::get()->getRoot();
	GenericStruct* mr = cr->get<GenericStruct>("module::Registrar");
	GenericStruct* mro = cr->get<GenericStruct>("module::Router");

	bool useGlobalDomain = mro->get<ConfigBoolean>("use-global-domain")->read();
	string dbImplementation = mr->get<ConfigString>("db-implementation")->read();
	string mMessageExpiresName = mr->get<ConfigString>("message-expires-param-name")->read();

	if ("internal" == dbImplementation) {
		LOGI("RegistrarDB implementation is internal");
		sUnique = make_unique<RegistrarDbInternal>(ag);
		sUnique->mUseGlobalDomain = useGlobalDomain;
	}
#ifdef ENABLE_REDIS
	/* Previous implementations allowed "redis-sync" and "redis-async", whereas we now expect "redis".
	 * We check that the dbImplementation _starts_ with "redis" now, so that we stay backward compatible. */
	else if (dbImplementation.find("redis") == 0) {
		LOGI("RegistrarDB implementation is REDIS");
		GenericStruct* registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
		RedisParameters params;
		params.domain = registrar->get<ConfigString>("redis-server-domain")->read();
		params.port = registrar->get<ConfigInt>("redis-server-port")->read();
		params.timeout = registrar->get<ConfigInt>("redis-server-timeout")->read();
		params.auth = [&registrar]() -> decltype(params.auth) {
			const auto& password = registrar->get<ConfigString>("redis-auth-password")->read();
			if (password.empty()) {
				return None();
			}
			const auto& user = registrar->get<ConfigString>("redis-auth-user")->read();
			if (user.empty()) {
				return Legacy{password};
			}
			return ACL{user, password};
		}();
		params.mSlaveCheckTimeout = chrono::seconds{registrar->get<ConfigInt>("redis-slave-check-period")->read()};
		params.useSlavesAsBackup = registrar->get<ConfigBoolean>("redis-use-slaves-as-backup")->read();

		sUnique = make_unique<RegistrarDbRedisAsync>(ag, params);
		sUnique->mUseGlobalDomain = useGlobalDomain;
		static_cast<RegistrarDbRedisAsync*>(sUnique.get())->connect();
	}
#endif
	else {
		LOGF("Unsupported implementation '%s'. %s",
#ifdef ENABLE_REDIS
		     "Supported implementations are 'internal' or 'redis'.", dbImplementation.c_str());
#else
		     "Supported implementation is 'internal'.", dbImplementation.c_str());
#endif
	}
	sUnique->mMessageExpiresName = mMessageExpiresName;
	return sUnique.get();
}

RegistrarDb* RegistrarDb::get() {
	if (sUnique == nullptr) {
		LOGF("RegistrarDb not initialized.");
	}
	return sUnique.get();
}

void RegistrarDb::clear(const MsgSip& sip, const shared_ptr<ContactUpdateListener>& listener) {
	doClear(sip, listener);
}

void RegistrarDb::clear(const SipUri& url,
                        const std::string& callId,
                        const std::shared_ptr<ContactUpdateListener>& listener) {
	// Forged message
	MsgSip msg(ownership::owned(nta_msg_create(mAgent->getSofiaAgent(), 0)));
	auto home = msg.getHome();
	auto sip = msg.getSip();
	sip->sip_from = sip_from_create(home, reinterpret_cast<const url_string_t*>(url.get()));
	sip->sip_call_id = sip_call_id_make(home, callId.c_str());
	sip->sip_cseq = sip_cseq_create(home, 0xDEADC0DE, SIP_METHOD_REGISTER); // Placeholder
	clear(msg, listener);
}

const string RegistrarDb::getMessageExpires(const msg_param_t* m_params) {
	if (m_params) {
		// Find message expires time in the contact parameters
		string mss_expires(*m_params);
		string name_expires_mss = RegistrarDb::get()->messageExpiresName();
		if (mss_expires.find(name_expires_mss + "=") != string::npos) {
			mss_expires =
			    mss_expires.substr(mss_expires.find(name_expires_mss + "=") + (strlen(name_expires_mss.c_str()) + 1));
			return mss_expires;
		}
	}
	return "";
}

class RecursiveRegistrarDbListener : public ContactUpdateListener,
                                     public enable_shared_from_this<RecursiveRegistrarDbListener> {
private:
	sofiasip::Home mHome;
	RegistrarDb* mDatabase = nullptr;
	shared_ptr<ContactUpdateListener> mOriginalListener;
	shared_ptr<Record> mRecord;
	int mPendingRequests = 1;
	int mStep = 0;
	SipUri mUrl;
	float mOriginalQ = 1.0; // the q parameter. When recursing, we choose to inherit it from the original target.
	bool mRecursionDone = false;
	static int sMaxStep;

public:
	RecursiveRegistrarDbListener(RegistrarDb* database,
	                             const shared_ptr<ContactUpdateListener>& original_listerner,
	                             const SipUri& url,
	                             int step = sMaxStep)
	    : mDatabase(database), mOriginalListener(original_listerner), mRecord(make_shared<Record>(url)), mStep(step),
	      mUrl(url) {
	}

	void onRecordFound(const shared_ptr<Record>& r) override {
		mPendingRequests--;
		if (r != nullptr) {
			auto& extlist = r->getExtendedContacts();
			list<shared_ptr<ExtendedContact>> vectToRecurseOn;
			auto& contacts = mRecord->getExtendedContacts();
			for (auto ec : extlist) {
				// Also add alias for late forking (context in the forks map for this alias key)
				SLOGD << "Step: " << mStep << (ec->mAlias ? "\tFound alias " : "\tFound contact ") << mUrl << " -> "
				      << ExtendedContact::urlToString(ec->mSipContact->m_url) << " usedAsRoute:" << ec->mUsedAsRoute;
				if (!ec->mAlias && ec->mUsedAsRoute) {
					ec = transformContactUsedAsRoute(mUrl.str(), ec);
				}
				contacts.emplace(ec);
				ec->mQ = ec->mQ * mOriginalQ;
				if (ec->mAlias && mStep > 0 && !mRecursionDone) {
					vectToRecurseOn.push_back(ec);
				}
			}
			mPendingRequests += vectToRecurseOn.size();
			mRecursionDone = true;
			for (auto itrec : vectToRecurseOn) {
				try {
					SipUri uri(itrec->mSipContact->m_url);
					auto listener =
					    make_shared<RecursiveRegistrarDbListener>(mDatabase, this->shared_from_this(), uri, mStep - 1);
					listener->mOriginalQ = itrec->mQ;
					mDatabase->fetch(uri, listener, false);
				} catch (const sofiasip::InvalidUrlError& e) {
					SLOGE << "Invalid fetched URI while fetching [" << mUrl.str() << "] recusively." << endl
					      << "The invalid URI is [" << e.getUrl() << "]. Reason: " << e.getReason();
				}
			}
		}

		if (waitPullUpOrFail()) {
			SLOGD << "Step: " << mStep << "\tNo contact found for " << mUrl;
			mOriginalListener->onRecordFound(nullptr);
		}
	}

	void onError() override {
		SLOGW << "Step: " << mStep << "\tError during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onError();
		}
	}

	void onInvalid() override {
		SLOGW << "Step: " << mStep << "\tInvalid during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onInvalid();
		}
	}

	void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
	}

private:
	shared_ptr<ExtendedContact> transformContactUsedAsRoute(const std::string& uri,
	                                                        const shared_ptr<ExtendedContact>& ec) {
		/* This function does the following:
		 * - make a copy of the extended contact
		 * - in this copy replace the main contact information by the 'uri' given in argument
		 * - append the main contact information of the original extended contact into the Path header of the new
		 * extended contact.
		 * While recursiving through alias, this allows to have a Route header appended for a "usedAsRoute" kind of
		 * Contact but still preserving
		 * the last request uri that was found recursed through the alias mechanism.
		 */
		shared_ptr<ExtendedContact> newEc = make_shared<ExtendedContact>(*ec);
		newEc->mSipContact =
		    sip_contact_create(newEc->mHome.home(), reinterpret_cast<const url_string_t*>(uri.c_str()), nullptr);
		ostringstream path;
		path << *ec->toSofiaUrlClean(newEc->mHome.home());
		newEc->mPath.push_back(path.str());
		// LOGD("transformContactUsedAsRoute(): path to %s added for %s", ec->mSipUri.c_str(), uri);
		newEc->mUsedAsRoute = false;
		return newEc;
	}

	bool waitPullUpOrFail() {
		if (mPendingRequests != 0) return false; // wait for all pending responses

		// No more results expected for this recursion level
		if (mRecord->getExtendedContacts().empty()) {
			return true; // no contacts collected on below recursion levels
		}

		// returning records collected on below recursion levels
		SLOGD << "Step: " << mStep << "\tReturning collected records " << mRecord->getExtendedContacts().size();
		mOriginalListener->onRecordFound(mRecord);
		return false;
	}
};

// Max recursive step
int RecursiveRegistrarDbListener::sMaxStep = 1;

void RegistrarDb::fetch(const SipUri& url, const shared_ptr<ContactUpdateListener>& listener, bool recursive) {
	fetch(url, listener, false, recursive);
}

void RegistrarDb::fetch(const SipUri& url,
                        const shared_ptr<ContactUpdateListener>& listener,
                        bool includingDomains,
                        bool recursive) {
	if (includingDomains) {
		fetchWithDomain(url, listener, recursive);
		return;
	}
	auto gr = UriUtils::getParamValue(url.get()->url_params, "gr");
	if (!gr.empty()) {
		doFetchInstance(url, UriUtils::grToUniqueId(gr),
		                recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url) : listener);
	} else {
		doFetch(url, recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url) : listener);
	}
}

void RegistrarDb::fetchList(const vector<SipUri> urls, const shared_ptr<ListContactUpdateListener>& listener) {
	class InternalContactUpdateListener : public ContactUpdateListener {
	public:
		InternalContactUpdateListener(shared_ptr<ListContactUpdateListener> listener, size_t size)
		    : listListener(listener), count(size) {
		}

	private:
		void onError() override {
			SLOGE << "Error while fetching contact";
			updateCount();
		}
		void onInvalid() override {
			SLOGE << "Invalid fetch of contact";
			updateCount();
		}
		void onRecordFound(const shared_ptr<Record>& r) override {
			SLOGI << "Contact fetched";
			if (r) listListener->records.push_back(r);
			updateCount();
		}
		void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
		}
		void updateCount() {
			count--;
			if (count == 0) listListener->onContactsUpdated();
		}

		shared_ptr<ListContactUpdateListener> listListener;
		size_t count;
	};

	shared_ptr<InternalContactUpdateListener> urlListener =
	    make_shared<InternalContactUpdateListener>(listener, urls.size());
	for (const auto& url : urls) {
		fetch(url, urlListener);
	}
}

url_t* RegistrarDb::synthesizePubGruu(su_home_t* home, const MsgSip& sipMsg) {
	sip_t* sip = sipMsg.getSip();
	if (!sip->sip_contact || !sip->sip_contact->m_params) return nullptr;
	if (!sip->sip_supported || msg_params_find(sip->sip_supported->k_items, "gruu") == nullptr) return nullptr;
	const char* instance_param = msg_params_find(sip->sip_contact->m_params, "+sip.instance");
	if (!instance_param) return nullptr;

	string gr = UriUtils::uniqueIdToGr(instance_param);
	if (gr.empty()) return nullptr;
	url_t* gruuUri = url_hdup(home, sip->sip_from->a_url);
	url_param_add(home, gruuUri, (string("gr=") + gr).c_str());
	return gruuUri;
}

void RegistrarDb::bind(const MsgSip& sipMsg,
                       const BindingParameters& parameter,
                       const shared_ptr<ContactUpdateListener>& listener) {
	/* Copy the SIP message because the below code modifies the message whereas bind() API suggests that it does not. */
	bind(MsgSip(sipMsg), parameter, listener);
}

void RegistrarDb::bind(MsgSip&& sipMsg,
                       const BindingParameters& parameter,
                       const shared_ptr<ContactUpdateListener>& listener) {
	sip_t* sip = sipMsg.getSip();

	bool gruu_assigned = false;
	if (mGruuEnabled) {
		url_t* gruuUri = synthesizePubGruu(sipMsg.getHome(), sipMsg);
		if (gruuUri) {
			/* assign a public gruu address to this contact */
			msg_header_replace_param(
			    sipMsg.getHome(), (msg_common_t*)sip->sip_contact,
			    su_sprintf(sipMsg.getHome(), "pub-gruu=\"%s\"", url_as_string(sipMsg.getHome(), gruuUri)));
			gruu_assigned = true;
		}
	}
	if (!gruu_assigned) {
		/* Set an empty pub-gruu meaning that this client hasn't requested any pub-gruu from this server.
		 * This is to preserve compatibility with previous RegistrarDb storage, where only gr parameter was stored.
		 * This couldn't work because a client can use a "gr" parameter in its contact uri.*/
		msg_header_replace_param(sipMsg.getHome(), (msg_common_t*)sip->sip_contact,
		                         su_sprintf(sipMsg.getHome(), "pub-gruu"));
	}

	int countSipContacts = this->countSipContacts(sip->sip_contact);
	if (countSipContacts > Record::getMaxContacts()) {
		LOGD("Too many contacts in register %s %i > %i", Record::defineKeyFromUrl(sip->sip_from->a_url).c_str(),
		     countSipContacts, Record::getMaxContacts());
		listener->onError();
		return;
	}

	LOGI("RegistrarDb: binding %s", SipUri(sipMsg.getSip()->sip_from->a_url).str().c_str());
	doBind(sipMsg, parameter, listener);
}

void RegistrarDb::bind(const SipUri& aor,
                       const sip_contact_t* contact,
                       const BindingParameters& parameter,
                       const shared_ptr<ContactUpdateListener>& listener) {
	MsgSip msg{};
	auto* homeSip = msg.getHome();
	auto* sip = msg.getSip();

	sip->sip_contact = sip_contact_dup(homeSip, contact);

	sip->sip_from = sip_from_create(homeSip, reinterpret_cast<const url_string_t*>(aor.get()));

	if (!parameter.path.empty()) {
		sip->sip_path = sip_path_format(homeSip, "<%s>", parameter.path.c_str());
	}

	if (!parameter.userAgent.empty()) {
		sip->sip_user_agent = sip_user_agent_make(homeSip, parameter.userAgent.c_str());
	}

	if (parameter.withGruu) {
		sip->sip_supported =
		    reinterpret_cast<sip_supported_t*>(sip_header_format(homeSip, sip_supported_class, "gruu"));
	}

	if (!parameter.callId.empty()) {
		sip->sip_call_id = sip_call_id_make(homeSip, parameter.callId.c_str());
	}

	if (0 <= parameter.cSeq) {
		sip->sip_cseq = sip_cseq_create(homeSip, parameter.cSeq, sip_method_register, nullptr);
	}

	sip->sip_expires = sip_expires_create(homeSip, 0);

	bind(std::move(msg), parameter, listener);
}

class AgregatorRegistrarDbListener : public ContactUpdateListener {
private:
	shared_ptr<ContactUpdateListener> mOriginalListener;
	int mNumRespExpected;
	int mNumResponseObtained;
	shared_ptr<Record> mRecord;
	bool mError;
	shared_ptr<Record> getRecord() {
		if (mRecord == nullptr) mRecord = make_shared<Record>(SipUri{});
		return mRecord;
	}
	void checkFinished() {
		mNumResponseObtained++;
		if (mNumResponseObtained == mNumRespExpected) {
			if (mError && mRecord == nullptr) {
				mOriginalListener->onError();
			} else {
				mOriginalListener->onRecordFound(mRecord);
			}
		}
	}

public:
	AgregatorRegistrarDbListener(const shared_ptr<ContactUpdateListener>& origListener, int numResponseExpected)
	    : mOriginalListener(origListener), mNumRespExpected(numResponseExpected), mNumResponseObtained(0), mRecord(0) {
		mError = false;
	}
	virtual ~AgregatorRegistrarDbListener() {
	}
	virtual void onRecordFound(const shared_ptr<Record>& r) override {
		if (r) {
			getRecord()->appendContactsFrom(r);
		}
		checkFinished();
	}
	virtual void onError() override {
		mError = true;
		checkFinished();
	}
	virtual void onInvalid() override {
		// onInvalid() will normally never be called for a fetch request
		checkFinished();
	}

	virtual void onContactUpdated([[maybe_unused]] const shared_ptr<ExtendedContact>& ec) override {
	}
};

void RegistrarDb::fetchWithDomain(const SipUri& url,
                                  const shared_ptr<ContactUpdateListener>& listener,
                                  bool recursive) {
	if (!url.getUser().empty()) {
		/* If username is present in URI, search with and without the username */
		auto domainOnlyUrl = url.replaceUser("");
		auto agregator = make_shared<AgregatorRegistrarDbListener>(listener, 2);
		fetch(url, agregator, recursive);
		fetch(domainOnlyUrl, agregator, false);
	} else {
		/* else do a single search of course. */
		fetch(url, listener, recursive);
	}
}

} // namespace flexisip
