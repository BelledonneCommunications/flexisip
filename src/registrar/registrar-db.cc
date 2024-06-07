/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "registrar-db.hh"

#include <memory>

#include "flexisip/configmanager.hh"
#include "flexisip/registrar/registar-listeners.hh"
#include "flexisip/sofia-wrapper/msg-sip.hh"
#include "flexisip/utils/sip-uri.hh"

#include "extended-contact.hh"
#include "record.hh"
#include "registrar/binding-parameters.hh"
#include "registrardb-internal.hh"
#include "utils/uri-utils.hh"

#if ENABLE_REDIS
#include "registrardb-redis.hh"
#endif

using namespace std;

namespace flexisip {

RegistrarDb::RegistrarDb(const std::shared_ptr<sofiasip::SuRoot>& root, const std::shared_ptr<ConfigManager>& cfg)
    : mRoot{root}, mConfigManager{cfg}, mRecordConfig{*cfg} {
	const GenericStruct* cr = mConfigManager->getRoot();
	const GenericStruct* mr = cr->get<GenericStruct>("module::Registrar");
	mGruuEnabled = mr->get<ConfigBoolean>("enable-gruu")->read();
	string dbImplementation = mr->get<ConfigString>("db-implementation")->read();

	const auto& notifyContact = [this](const auto& key, const auto& uid) {
		if (!uid.has_value()) {
			// Unreachable, see REDISPUBSUBFORMAT
			SLOGE << "RegistrarDb::notifyContactListenerCallback: Subscription failed, erasing all listeners for " << key;
			this->mContactListenersMap.erase(key.asString());
			return;
		}

		this->notifyContactListener(key, *uid);
	};
	if ("internal" == dbImplementation) {
		LOGI("RegistrarDB implementation is internal");
		mBackend = make_unique<RegistrarDbInternal>(mRecordConfig, mLocalRegExpire, notifyContact);
	}
#ifdef ENABLE_REDIS
	/* Previous implementations allowed "redis-sync" and "redis-async", whereas we now expect "redis".
	 * We check that the dbImplementation _starts_ with "redis" now, so that we stay backward compatible. */
	else if (dbImplementation.find("redis") == 0) {
		LOGI("RegistrarDB implementation is REDIS");
		const GenericStruct* registrar = cr->get<GenericStruct>("module::Registrar");
		redis::async::RedisParameters params;
		params.domain = registrar->get<ConfigString>("redis-server-domain")->read();
		params.port = registrar->get<ConfigInt>("redis-server-port")->read();
		params.timeout = registrar->get<ConfigDuration<chrono::milliseconds>>("redis-server-timeout")->read().count();
		params.auth = [&registrar]() -> decltype(params.auth) {
			using namespace redis::auth;

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
		params.mSlaveCheckTimeout = chrono::duration_cast<chrono::seconds>(
		    registrar->get<ConfigDuration<chrono::seconds>>("redis-slave-check-period")->read());
		params.useSlavesAsBackup = registrar->get<ConfigBoolean>("redis-use-slaves-as-backup")->read();

		auto notifyState = [this](bool bWritable) { this->notifyStateListener(bWritable); };
		mBackend = make_unique<RegistrarDbRedisAsync>(*mRoot, mRecordConfig, mLocalRegExpire, params, notifyContact,
		                                              notifyState);
		static_cast<RegistrarDbRedisAsync*>(mBackend.get())->connect();
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
}

void RegistrarDb::addStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	auto it = find(mStateListeners.cbegin(), mStateListeners.cend(), listener);
	if (it == mStateListeners.cend()) mStateListeners.push_back(listener);
}

void RegistrarDb::removeStateListener(const std::shared_ptr<RegistrarDbStateListener>& listener) {
	mStateListeners.remove(listener);
}

void RegistrarDb::notifyStateListener(bool bWritable) const {
	for (auto& listener : mStateListeners)
		listener->onRegistrarDbWritable(bWritable);
}

bool RegistrarDb::subscribe(const Record::Key& key, std::weak_ptr<ContactRegisteredListener>&& listener) {
	const auto& topic = key.asString();
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
	mBackend->subscribe(key);
	return true;
}

void RegistrarDb::unsubscribe(const Record::Key& key, const shared_ptr<ContactRegisteredListener>& listener) {
	const auto& topic = key.asString();
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
	if (0 < mContactListenersMap.count(topic)) return;
	mBackend->unsubscribe(key);
}

void RegistrarDb::publish(const Record::Key& key, const string& uid) {
	SLOGD << "Publish topic = " << key << ", uid = " << uid;
	mBackend->publish(key, uid);
}

class ContactNotificationListener : public ContactUpdateListener,
                                    public std::enable_shared_from_this<ContactNotificationListener> {
public:
	ContactNotificationListener(std::string_view uid, RegistrarDb* db, const SipUri& aor)
	    : mUid(uid), mDb(db), mAor(aor) {
	}

private:
	// ContactUpdateListener implementation
	void onRecordFound(const shared_ptr<Record>& r) override {
		auto record = r ?: make_shared<Record>(mAor, mDb->getRecordConfig());
		mDb->notifyContactListener(record, mUid);
	}
	void onError(const SipStatus&) override {
	}
	void onInvalid(const SipStatus&) override {
	}
	void onContactUpdated([[maybe_unused]] const std::shared_ptr<ExtendedContact>& ec) override {
	}

	string mUid;
	RegistrarDb* mDb = nullptr;
	SipUri mAor;
};

void RegistrarDb::notifyContactListener(const Record::Key& key, std::string_view uid) {
	const auto& sipUri = key.toSipUri();
	auto listener = make_shared<ContactNotificationListener>(uid, this, sipUri);
	SLOGD << "Notify topic = " << key << ", uid = " << uid;
	fetch(sipUri, listener, true);
}

void RegistrarDb::notifyContactListener(const shared_ptr<Record>& r, const string& uid) {
	auto range = mContactListenersMap.equal_range(r->getKey().asString());

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
		SLOGD << "Notify topic = " << r->getKey() << " to listener " << l.get();
		l->onContactRegistered(r, uid);
	}
}

void LocalRegExpire::update(const shared_ptr<Record>& record) {
	unique_lock<mutex> lock(mMutex);
	time_t latest = record->latestExpire(mLatestExpirePredicate);
	if (latest > 0) {
		auto it = mRegMap.find(record->getKey().asString());
		if (it != mRegMap.end()) {
			(*it).second = latest;
		} else {
			if (!record->isEmpty() && !record->haveOnlyStaticContacts()) {
				mRegMap.insert(make_pair(record->getKey().asString(), latest));
				notifyLocalRegExpireListener(mRegMap.size());
			}
		}
	} else {
		mRegMap.erase(record->getKey().asString());
		notifyLocalRegExpireListener(mRegMap.size());
	}
}

size_t LocalRegExpire::countActives() {
	return mRegMap.size();
}
void LocalRegExpire::removeExpiredBefore(time_t before) {
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

void LocalRegExpire::getRegisteredAors(std::list<std::string>& aors) const {
	unique_lock<mutex> lock(mMutex);
	for (auto& pair : mRegMap) {
		aors.push_back(pair.first);
	}
}

void LocalRegExpire::subscribe(LocalRegExpireListener* listener) {
	LOGD("Subscribe LocalRegExpire");
	mLocalRegListenerList.push_back(listener);
}

void LocalRegExpire::unsubscribe(LocalRegExpireListener* listener) {
	LOGD("Unsubscribe LocalRegExpire");
	auto result = find(mLocalRegListenerList.begin(), mLocalRegListenerList.end(), listener);
	if (result != mLocalRegListenerList.end()) {
		mLocalRegListenerList.erase(result);
	}
}

void LocalRegExpire::notifyLocalRegExpireListener(unsigned int count) {
	LOGD("Notify LocalRegExpire count = %d", count);
	for (auto& listener : mLocalRegListenerList) {
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

void RegistrarDb::clear(const MsgSip& sip, const shared_ptr<ContactUpdateListener>& listener) {
	mBackend->doClear(sip, listener);
}

void RegistrarDb::clear(const SipUri& url,
                        const std::string& callId,
                        const std::shared_ptr<ContactUpdateListener>& listener) {
	// Forged message
	MsgSip msg{};
	auto* home = msg.getHome();
	auto* sip = msg.getSip();
	sip->sip_from = sip_from_create(home, reinterpret_cast<const url_string_t*>(url.get()));
	sip->sip_call_id = sip_call_id_make(home, callId.c_str());
	sip->sip_cseq = sip_cseq_create(home, 0xDEADC0DE, SIP_METHOD_REGISTER); // Placeholder
	clear(msg, listener);
}

class RecursiveRegistrarDbListener : public ContactUpdateListener,
                                     public enable_shared_from_this<RecursiveRegistrarDbListener> {
private:
	sofiasip::Home mHome;
	RegistrarDb* mDatabase = nullptr;
	shared_ptr<ContactUpdateListener> mOriginalListener;
	shared_ptr<Record> mRecord;
	SipUri mUrl;
	int mPendingRequests = 1;
	int mStep = 0;
	float mOriginalQ = 1.0; // the q parameter. When recursing, we choose to inherit it from the original target.
	bool mRecursionDone = false;
	static int sMaxStep;

public:
	RecursiveRegistrarDbListener(RegistrarDb* database,
	                             const shared_ptr<ContactUpdateListener>& original_listerner,
	                             const SipUri& url,
	                             int step = sMaxStep)
	    : mDatabase(database), mOriginalListener(original_listerner),
	      mRecord(make_shared<Record>(url, mDatabase->getRecordConfig())), mUrl(url), mStep(step) {
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

	void onError(const SipStatus& response) override {
		SLOGW << "Step: " << mStep << "\tError during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onError(response);
		}
	}

	void onInvalid(const SipStatus& response) override {
		SLOGW << "Step: " << mStep << "\tInvalid during recursive fetch of " << mUrl;
		if (waitPullUpOrFail()) {
			mOriginalListener->onInvalid(response);
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
		mBackend->doFetchInstance(url, UriUtils::grToUniqueId(gr),
		                          recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url)
		                                    : listener);
	} else {
		mBackend->doFetch(url, recursive ? make_shared<RecursiveRegistrarDbListener>(this, listener, url) : listener);
	}
}

void RegistrarDb::fetchList(const vector<SipUri> urls, const shared_ptr<ListContactUpdateListener>& listener) {
	class InternalContactUpdateListener : public ContactUpdateListener {
	public:
		InternalContactUpdateListener(shared_ptr<ListContactUpdateListener> listener, size_t size)
		    : listListener(listener), count(size) {
		}

	private:
		void onError(const SipStatus&) override {
			SLOGE << "Error while fetching contact";
			updateCount();
		}
		void onInvalid(const SipStatus&) override {
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
	auto* sip = sipMsg.getSip();
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

	int countSipContacts = RegistrarDb::countSipContacts(sip->sip_contact);
	const auto maxContacts = mRecordConfig.getMaxContacts();
	if (countSipContacts > maxContacts) {
		SLOGD << "Too many contacts in register " << Record::Key(sip->sip_from->a_url, mRecordConfig.useGlobalDomain())
		      << " " << countSipContacts << " > " << maxContacts;
		listener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
		return;
	}

	LOGI("RegistrarDb: binding %s", SipUri(sipMsg.getSip()->sip_from->a_url).str().c_str());
	mBackend->doBind(sipMsg, parameter, listener);
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
	sip->sip_path = parameter.path.toSofiaType(homeSip);

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
	const Record::Config& mRecordConfig;
	shared_ptr<Record> mRecord;
	bool mError;
	shared_ptr<Record> getRecord() {
		if (mRecord == nullptr) mRecord = make_shared<Record>(SipUri{}, mRecordConfig);
		return mRecord;
	}
	void checkFinished() {
		mNumResponseObtained++;
		if (mNumResponseObtained == mNumRespExpected) {
			if (mError && mRecord == nullptr) {
				mOriginalListener->onError(SipStatus(SIP_500_INTERNAL_SERVER_ERROR));
			} else {
				mOriginalListener->onRecordFound(mRecord);
			}
		}
	}

public:
	AgregatorRegistrarDbListener(const shared_ptr<ContactUpdateListener>& origListener,
	                             int numResponseExpected,
	                             const Record::Config& recordConfig)
	    : mOriginalListener(origListener), mNumRespExpected(numResponseExpected), mNumResponseObtained(0),
	      mRecordConfig(recordConfig), mRecord(0) {
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
	virtual void onError(const SipStatus&) override {
		mError = true;
		checkFinished();
	}
	virtual void onInvalid(const SipStatus&) override {
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
		auto agregator = make_shared<AgregatorRegistrarDbListener>(listener, 2, mRecordConfig);
		fetch(url, agregator, recursive);
		fetch(domainOnlyUrl, agregator, false);
	} else {
		/* else do a single search of course. */
		fetch(url, listener, recursive);
	}
}

} // namespace flexisip
