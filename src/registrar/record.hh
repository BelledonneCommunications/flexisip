/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <list>
#include <memory>
#include <string>

#include "flexisip/sofia-wrapper/home.hh"
#include "flexisip/utils/sip-uri.hh"

namespace flexisip {

class Agent;
class ChangeSet;
class ContactUpdateListener;
struct BindingParameters;
struct ExtendedContact;
struct ExtendedContactCommon;

class Record {
	friend class RegistrarDb;

private:
	static void init();

	sofiasip::Home mHome;
	std::list<std::shared_ptr<ExtendedContact>> mContacts; /* The full list of contacts */
	std::string mKey;
	SipUri mAor;
	bool mIsDomain = false; /*is a domain registration*/
	bool mOnlyStaticContacts = true;
	static void eliminateAmbiguousContacts(std::list<std::unique_ptr<ExtendedContact>>& extendedContacts);

	enum class ContactMatch {
		Skip,           // Does not match the newly registered contact. Nothing to do.
		EraseAndNotify, // Update or Remove
		ForceErase,     // Service clean up
	};

	static ContactMatch matchContacts(const ExtendedContact& existing, const ExtendedContact& neo);

public:
	static std::list<std::string> sLineFieldNames;
	static int sMaxContacts;
	static bool sAssumeUniqueDomains;

	Record(const SipUri& aor);
	Record(SipUri&& aor);
	Record(const Record& other) = delete; // disable copy constructor, this is unsafe due to su_home_t here.
	Record(Record&& other) = delete;      // disable move constructor
	~Record() = default;

	Record& operator=(const Record& other) = delete; // disable assignement operator too
	Record& operator=(Record&& other) = delete;      // disable move assignement operator too

	// Get address of record
	const SipUri& getAor() const {
		return mAor;
	}

	/**
	 * @throws InvalidCseq when the contact has a CSeq less than or equal to that of a matching contact in the record
	 * (only when updating based on RFC 3261 URI matching rules. I.e. cannot happen when updating based on
	 * +sip.instance)
	 */
	ChangeSet insertOrUpdateBinding(std::unique_ptr<ExtendedContact>&& ec, ContactUpdateListener* listener);

	const std::shared_ptr<ExtendedContact> extractContactByUniqueId(const std::string& uid) const;
	sip_contact_t* getContacts(su_home_t* home);
	void pushContact(const std::shared_ptr<ExtendedContact>& ct) {
		mContacts.push_back(ct);
	}

	std::list<std::shared_ptr<ExtendedContact>>::iterator removeContact(const std::shared_ptr<ExtendedContact>& ct) {
		return mContacts.erase(find(mContacts.begin(), mContacts.end(), ct));
	}
	void clean(time_t time, const std::shared_ptr<ContactUpdateListener>& listener);

	/**
	 * @throws InvalidCseq when a contact has a CSeq less than or equal to that of a matching contact in the record
	 * (only when updating based on RFC 3261 URI matching rules. I.e. cannot happen when updating based on
	 * +sip.instance)
	 */
	ChangeSet update(const sip_t* sip,
	                 const BindingParameters& parameters,
	                 const std::shared_ptr<ContactUpdateListener>& listener);
	// Deprecated: this one is used by protobuf serializer
	void update(const ExtendedContactCommon& ecc,
	            const char* sipuri,
	            long int expireAt,
	            float q,
	            uint32_t cseq,
	            time_t updated_time,
	            bool alias,
	            const std::list<std::string> accept,
	            bool usedAsRoute,
	            const std::shared_ptr<ContactUpdateListener>& listener);
	bool updateFromUrlEncodedParams(const char* uid, const char* full_url);

	void print(std::ostream& stream) const;
	bool isEmpty() const {
		return mContacts.empty();
	}
	const std::string& getKey() const {
		return mKey;
	}
	int count() {
		return mContacts.size();
	}
	const std::list<std::shared_ptr<ExtendedContact>>& getExtendedContacts() const {
		return mContacts;
	}

	/*
	 * Synthetise the pub-gruu address from an extended contact belonging to this Record.
	 * FIXME: of course this method should be directly attached to ExtendedContact.
	 * Unfortunately, because pub-gruu were not contained in the ExtendedContact, it shall remain in Record for
	 * compatibility.
	 */
	url_t* getPubGruu(const std::shared_ptr<ExtendedContact>& ec, su_home_t* home);
	/**
	 * Check if the contacts list size is < to max aor config option and remove older contacts to match restriction if
	 * needed
	 */
	ChangeSet applyMaxAor();
	static int getMaxContacts() {
		if (sMaxContacts == -1) init();
		return sMaxContacts;
	}
	time_t latestExpire() const;
	time_t latestExpire(Agent* ag) const;
	static std::list<std::string> route_to_stl(const sip_route_s* route);
	void appendContactsFrom(const std::shared_ptr<Record>& src);
	bool haveOnlyStaticContacts() const {
		return mOnlyStaticContacts;
	}
	bool isSame(const Record& other) const;

	// A null pointer or an empty AOR leads to an empty key.
	static std::string defineKeyFromUrl(const url_t* aor);
	static SipUri makeUrlFromKey(const std::string& key);
	static std::string extractUniqueId(const sip_contact_t* contact);
};

template <typename TraitsT>
inline std::basic_ostream<char, TraitsT>& operator<<(std::basic_ostream<char, TraitsT>& strm, const Record& record) {
	record.print(strm);
	return strm;
}

} // namespace flexisip
