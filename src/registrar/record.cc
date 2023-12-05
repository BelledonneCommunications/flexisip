/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "record.hh"

#include "flexisip/registrar/registar-listeners.hh"

#include "agent.hh"
#include "binding-parameters.hh"
#include "change-set.hh"
#include "eventlogs/writers/event-log-writer.hh"
#include "exceptions.hh"
#include "extended-contact.hh"
#include "registrar-db.hh"

using namespace std;

namespace flexisip {

sip_contact_t* Record::getContacts(su_home_t* home) {
	sip_contact_t* alist = nullptr;
	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		sip_contact_t* current = (*it)->toSofiaContact(home);
		if (alist) {
			current->m_next = alist;
		}
		alist = current;
	}
	return alist;
}

string Record::extractUniqueId(const sip_contact_t* contact) {
	char lineValue[256] = {0};

	/*search for device unique parameter among the ones configured */
	for (auto it = sLineFieldNames.begin(); it != sLineFieldNames.end(); ++it) {
		const char* ct_param = msg_params_find(contact->m_params, it->c_str());
		if (ct_param) return ct_param;
		if (url_param(contact->m_url->url_params, it->c_str(), lineValue, sizeof(lineValue) - 1) > 0) {
			return lineValue;
		}
	}

	return "";
}

const shared_ptr<ExtendedContact> Record::extractContactByUniqueId(const string& uid) const {
	const auto contacts = getExtendedContacts();
	for (auto it = contacts.begin(); it != contacts.end(); ++it) {
		const shared_ptr<ExtendedContact> ec = *it;
		if (ec && ec->mKey.str().compare(uid) == 0) {
			return ec;
		}
	}
	shared_ptr<ExtendedContact> noContact;
	return noContact;
}

/**
 * Should first have checked the validity of the register with isValidRegister.
 */
void Record::clean(const shared_ptr<ContactUpdateListener>& listener) {
	auto it = mContacts.begin();
	while (it != mContacts.end()) {
		shared_ptr<ExtendedContact> ec = (*it);
		if (ec->isExpired()) {
			if (listener) listener->onContactUpdated(ec);
			it = mContacts.erase(it);
		} else {
			++it;
		}
	}
}

time_t Record::latestExpire() const {
	time_t latest = 0;
	for (const auto& contact : mContacts) {
		latest = std::max(latest, contact->getExpireTime());
	}
	return latest;
}

time_t Record::latestExpire(Agent* ag) const {
	time_t latest = 0;
	sofiasip::Home home;

	for (auto it = mContacts.begin(); it != mContacts.end(); ++it) {
		const auto expireTime = (*it)->getExpireTime();
		if ((*it)->mPath.empty() || expireTime <= latest) continue;

		/* Remove extra parameters */
		string s = *(*it)->mPath.begin();
		string::size_type n = s.find(";");
		if (n != string::npos) s = s.substr(0, n);
		url_t* url = url_make(home.home(), s.c_str());

		if (ag->isUs(url)) latest = expireTime;
	}
	return latest;
}

list<string> Record::route_to_stl(const sip_route_s* route) {
	list<string> res;
	sofiasip::Home home;
	while (route != nullptr) {
		res.push_back(string(url_as_string(home.home(), route->r_url)));
		route = route->r_next;
	}
	return res;
}

string Record::defineKeyFromUrl(const url_t* url) {
	ostringstream ostr;
	if (url == nullptr) return string{};
	const char* user = url->url_user;
	if (user && user[0] != '\0') {
		if (!RegistrarDb::get()->useGlobalDomain()) {
			ostr << user << "@" << url->url_host;
		} else {
			ostr << user << "@"
			     << "merged";
		}
	} else {
		ostr << url->url_host;
	}
	return ostr.str();
}

SipUri Record::makeUrlFromKey(const string& key) {
	return SipUri("sip:" + key);
}

ChangeSet Record::insertOrUpdateBinding(unique_ptr<ExtendedContact>&& ec, ContactUpdateListener* listener) {
	SLOGD << "Updating record with contact " << *ec;
	ChangeSet changeSet{};

	if (sAssumeUniqueDomains && mIsDomain) {
		for (auto& ct : mContacts)
			changeSet.mDelete.push_back(ct);
		mContacts.clear();
	}

	auto alreadyMatched = false; // If multiple existing contacts match the new contact (e.g. based on URI) then we
	                             // update the first one, and delete the others
	for (auto it = mContacts.begin(); it != mContacts.end();) {
		auto existing = *it;
		auto remove = true;

		switch (matchContacts(*existing, *ec)) {
			case ContactMatch::Skip:
				it++;
				break;
			case ContactMatch::EraseAndNotify: {
				if (listener) listener->onContactUpdated(existing);
				remove = ec->isExpired() || alreadyMatched;
			}
			/* fallthrough */
			case ContactMatch::ForceErase:
				if (remove) {
					SLOGD << "Removing " << *existing;
					changeSet.mDelete.push_back(existing);
				} else {
					SLOGD << "Updating " << *existing;

					// Carry over existing key
					// (otherwise the contact would get duplicated instead of updated)
					ec->mKey = existing->mKey;
					alreadyMatched = true;
				}
				it = mContacts.erase(it);
				break;
		}
	}

	if (ec->mCallId.find("static-record") == string::npos) {
		mOnlyStaticContacts = false;
	}

	/* Add the new contact, if not expired (ie with expires=0) */
	if (!ec->isExpired()) {
		shared_ptr<ExtendedContact> shared = move(ec);
		mContacts.emplace(shared);
		changeSet.mUpsert.push_back(shared);
	}

	return changeSet;
}

Record::ContactMatch Record::matchContacts(const ExtendedContact& existing, const ExtendedContact& neo) {
	if (existing.mPushParamList == neo.mPushParamList) {
		if (existing.getRegisterTime() <= neo.getRegisterTime()) {
			SLOGD << "Removing contact [" << existing.contactId() << "] with identical push params : new["
			      << neo.mPushParamList << "], current[" << existing.mPushParamList << "]";
			return ContactMatch::ForceErase;
		} else {
			SLOGW << "Inserted contact has the same push parameters as another more recent contact, this should not "
			         "happen. (existing: "
			      << existing.getRegisterTime() << " ≮ new: " << neo.getRegisterTime() << ")";
		}
	}

	// Existing contact has an instance-id that is not a placeholder. RFC 5626
	if (!existing.mKey.isPlaceholder()) {
		if (existing.mKey == neo.mKey) {
			SLOGD << "Contact [" << existing << "] matches [" << neo << "] based on unique id";
			return ContactMatch::EraseAndNotify;
		}

		return ContactMatch::Skip; // no need to match further
	}

	// Otherwise, "If the Contact header field does not contain a "+sip.instance" Contact header field parameter, the
	// registrar processes the request using the Contact binding rules in [RFC3261]." (RFC 5626 §6)

	// "For each address, the registrar […] searches the list of current bindings using the URI comparison rules."
	// (RFC 3261 §10.3)
	if (SipUri(existing.mSipContact->m_url).rfc3261Compare(neo.mSipContact->m_url)) {
		SLOGD << "Contact [" << existing << "] matches [" << neo << "] based on URI";
		// "If the binding does exist, the registrar checks the Call-ID value. If the Call-ID value in the existing
		// binding differs from the Call-ID value in the request, the binding MUST be removed [or] updated. If they are
		// the same, the registrar compares the CSeq value. If the value is higher than that of the existing binding, it
		// MUST update or remove the binding as above." (RFC 3261 §10.3)
		if (existing.mCallId != neo.mCallId || existing.mCSeq < neo.mCSeq) {
			return ContactMatch::EraseAndNotify;
		};

		// "If not, the update MUST be aborted and the request fails." (RFC 3261 §10.3)
		SLOGD << "Existing contact [" << existing << "] has a higher CSeq value than request [" << neo << "]";
		throw InvalidCSeq();
	}

	if (existing.isExpired()) {
		SLOGD << "Cleaning expired contact '" << existing.contactId() << "'";
		return ContactMatch::ForceErase;
	}

	return ContactMatch::Skip;
}

ChangeSet Record::applyMaxAor() {
	ChangeSet changeSet{};
	while (mContacts.size() > static_cast<size_t>(sMaxContacts)) {
		const auto oldest = mContacts.oldest();
		changeSet.mDelete.push_back(*oldest);
		mContacts.erase(oldest);
	}

	return changeSet;
}

void Record::eliminateAmbiguousContacts(list<unique_ptr<ExtendedContact>>& extendedContacts) {
	/* This happens when a client (like Linphone) sends this kind of very ambiguous Contact header in a REGISTER
	 * Contact:
	 * <sip:marie_-jSau@ip1:39936;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>"
	 * Contact:
	 * <sip:marie_-jSau@ip1:39934;transport=tcp>;+sip.instance="<urn:uuid:bfb7514b-f793-4d85-b322-232044dc3731>";expires=0
	 * We want to drop the second one.
	 */
	for (auto it = extendedContacts.begin(); it != extendedContacts.end();) {
		auto& exc = *it;
		if (exc->getSipExpires() == 0s && !exc->mKey.isPlaceholder()) {
			auto duplicate =
			    find_if(extendedContacts.begin(), extendedContacts.end(),
			            [&exc](const auto& exc2) -> bool { return exc != exc2 && exc->mKey == exc2->mKey; });
			if (duplicate != extendedContacts.end()) {
				LOGD("Eliminating duplicate contact with unique id [%s]", exc->mKey.str().c_str());
				it = extendedContacts.erase(it);
				continue;
			}
		}
		++it;
	}
}
ChangeSet Record::removeInvalidContacts() {
	ChangeSet changeSet{};
	for (auto it = mContacts.begin(); it != mContacts.end();) {
		auto contact = *it;
		if (!isValidSipUri(contact->mSipContact->m_url)) {
			changeSet.mDelete.push_back(contact);
			SLOGD << "Removing invalid contact: " << contact->urlAsString();
			it = mContacts.erase(it);
		} else ++it;
	}
	return changeSet;
}

ChangeSet Record::update(const sip_t* sip,
                         const BindingParameters& parameters,
                         const shared_ptr<ContactUpdateListener>& listener) {
	list<string> stlPath;
	sofiasip::Home home;
	string userAgent;
	const sip_contact_t* contacts = sip->sip_contact;
	const sip_accept_t* accept = sip->sip_accept;
	list<string> acceptHeaders;
	list<unique_ptr<ExtendedContact>> extendedContacts;

	while (accept != nullptr) {
		acceptHeaders.push_back(accept->ac_type);
		accept = accept->ac_next;
	}

	if (sip->sip_path != nullptr) {
		stlPath = route_to_stl(sip->sip_path);
	}

	userAgent = (sip->sip_user_agent) ? sip->sip_user_agent->g_string : "";

	// Build ExtendedContacts from sip contacts.
	while (contacts) {
		string uniqueId = extractUniqueId(contacts);

		ExtendedContactCommon ecc(stlPath, sip->sip_call_id->i_id, uniqueId);
		bool alias = parameters.isAliasFunction ? parameters.isAliasFunction(contacts->m_url) : parameters.alias;
		auto exc = make_unique<ExtendedContact>(ecc, contacts, parameters.globalExpire,
		                                        (sip->sip_cseq) ? sip->sip_cseq->cs_seq : 0, getCurrentTime(), alias,
		                                        acceptHeaders, userAgent);
		exc->mUsedAsRoute = sip->sip_from->a_url->url_user == nullptr;
		extendedContacts.push_back(move(exc));
		contacts = contacts->m_next;
	}

	eliminateAmbiguousContacts(extendedContacts);

	// Update the Record.
	ChangeSet changeSet = removeInvalidContacts();
	for (auto& exc : extendedContacts) {
		changeSet += insertOrUpdateBinding(move(exc), listener.get());
	}

	changeSet += applyMaxAor();

	SLOGD << *this;
	return changeSet;
}

void Record::update(const ExtendedContactCommon& ecc,
                    const char* sipuri,
                    long expireAt,
                    [[maybe_unused]] float q,
                    uint32_t cseq,
                    time_t updated_time,
                    bool alias,
                    const list<string> accept,
                    bool usedAsRoute,
                    const shared_ptr<ContactUpdateListener>& listener) {
	sofiasip::Home home;
	url_t* sipUri = url_make(home.home(), sipuri);

	if (!sipUri) {
		LOGE("Record::update(): could not build sip uri.");
		return;
	}
	sip_contact_t* contact = sip_contact_create(home.home(), (url_string_t*)sipUri, nullptr);
	if (!contact) {
		LOGE("Record::update(): could not build contact.");
		return;
	}

	auto exct = make_unique<ExtendedContact>(ecc, contact, expireAt, cseq, updated_time, alias, accept, "");
	exct->mUsedAsRoute = usedAsRoute;
	try {
		insertOrUpdateBinding(move(exct), listener.get());
	} catch (const InvalidCSeq&) {
		SLOGE << "Unexpected invalid CSeq encountered when deserializing " << sipuri;
	}
	applyMaxAor();

	SLOGD << *this;
}

/* This function is designed for non-regression tests. It is not performant and non-exhaustive in the compararison */
bool Record::isSame(const Record& other) const {
	SLOGD << "Comparing " << this << "\nwith " << other;
	if (!getAor().compareAll(other.getAor())) {
		LOGD("Record::isSame(): aors differ.");
		return false;
	}
	if (getExtendedContacts().size() != other.getExtendedContacts().size()) {
		LOGD("Record::isSame(): number of extended contacts differ.");
		return false;
	}
	for (const auto& exc : getExtendedContacts()) {
		const auto& otherExc = extractContactByUniqueId(exc->mKey);
		if (otherExc == nullptr) {
			LOGD("Record::isSame(): no contact with uniqueId [%s] in other record.", exc->mKey.str().c_str());
			return false;
		}
		if (!exc->isSame(*otherExc)) {
			SLOGD << "Record::isSame(): contacts differ: [" << *this << "] <> [" << *otherExc << "]";
			return false;
		}
	}
	return true;
}

void Record::print(ostream& stream) const {
	time_t now = getCurrentTime();
	time_t offset = getTimeOffset(now);
	stream << "Record[" << this << "] {\n";
	stream << "mContacts (" << mContacts.size() << "): [";
	for (const auto& contact : mContacts) {
		stream << "\n\t";
		contact->print(stream, now, offset);
	}
	stream << "\n]}";

	// Example output:
	/* clang-format off

	Record[0x60f0000e46b0] {
	mContacts (3): [
			ExtendedContact[0x61200022ce40]( sip:existing1@example.org path="" user-agent="" alias=no uid=test-contact-0 expire=87 s (Thu Feb  9 15:01:00 2023) )
			ExtendedContact[0x61200022d2c0]( sip:existing2@example.org path="" user-agent="" alias=no uid=test-contact-1 expire=87 s (Thu Feb  9 15:01:00 2023) )
			ExtendedContact[0x61200022d740]( sip:existing3@example.org path="" user-agent="" alias=no uid=test-contact-2 expire=87 s (Thu Feb  9 15:01:00 2023) )
	]}

	clang-format on */
}

int Record::sMaxContacts = -1;
list<string> Record::sLineFieldNames;
bool Record::sAssumeUniqueDomains = false;

Record::Record(const SipUri& aor) : Record(SipUri(aor)) {
}

Record::Record(SipUri&& aor) : mAor(move(aor)) {
	// warning: aor is empty at this point. Use mAor!
	mKey = defineKeyFromUrl(mAor.get());
	mIsDomain = mAor.getUser().empty();
	if (sMaxContacts == -1) init();
}

url_t* Record::getPubGruu(const std::shared_ptr<ExtendedContact>& ec, su_home_t* home) {
	char gr_value[256] = {0};
	url_t* gruu_addr = NULL;
	const char* pub_gruu_value = msg_header_find_param((msg_common_t*)ec->mSipContact, "pub-gruu");

	if (pub_gruu_value) {
		if (pub_gruu_value[0] == '\0') {
			/*
			 * To preserve compatibility with previous storage of pub-gruu (where only a gr parameter was set in URI),
			 * a client that didn't requested a gruu address has now a "pub-gruu" contact parameter which is empty.
			 * This means that this client has no pub-gruu assigned by this server.
			 */
			return nullptr;
		}
		gruu_addr = url_make(home, StringUtils::unquote(pub_gruu_value).c_str());
		return gruu_addr;
	}

	/*
	 * Compatibility code, when pub-gruu wasn't stored in RegistrarDb.
	 * In such case, we have to synthetize the gruu address from the address of record and the gr uri parameter.
	 */

	if (!ec->mSipContact->m_url->url_params) return NULL;
	isize_t result = url_param(ec->mSipContact->m_url->url_params, "gr", gr_value, sizeof(gr_value) - 1);

	if (result > 0) {
		gruu_addr = url_hdup(home, mAor.get());
		url_param_add(home, gruu_addr, su_sprintf(home, "gr=%s", gr_value));
	}
	return gruu_addr;
}

void Record::init() {
	GenericStruct* registrar = GenericManager::get()->getRoot()->get<GenericStruct>("module::Registrar");
	sMaxContacts = registrar->get<ConfigInt>("max-contacts-by-aor")->read();
	sLineFieldNames = registrar->get<ConfigStringList>("unique-id-parameters")->read();
	sAssumeUniqueDomains = GenericManager::get()
	                           ->getRoot()
	                           ->get<GenericStruct>("inter-domain-connections")
	                           ->get<ConfigBoolean>("assume-unique-domains")
	                           ->read();
}

void Record::appendContactsFrom(const shared_ptr<Record>& src) {
	if (!src) return;

	for (const auto& contact : src->mContacts) {
		mContacts.emplace(contact);
	}
}

} // namespace flexisip
