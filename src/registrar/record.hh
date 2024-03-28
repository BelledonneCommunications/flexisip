/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2024 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <list>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "flexisip/configmanager.hh"
#include "flexisip/sofia-wrapper/home.hh"
#include "flexisip/utils/sip-uri.hh"

#include "extended-contact.hh"

namespace flexisip {

class ChangeSet;
class ContactUpdateListener;
struct BindingParameters;
struct ExtendedContact;
struct ExtendedContactCommon;

class Record {
	friend class RegistrarDb;

public:
	struct OrderByUpdateTime {
		bool operator()(const std::shared_ptr<ExtendedContact>& lhs,
		                const std::shared_ptr<ExtendedContact>& rhs) const {
			return lhs->getRegisterTime() < rhs->getRegisterTime();
		}
	};

	// multiset, because contacts may have the same update time
	class Contacts : public std::multiset<std::shared_ptr<ExtendedContact>, OrderByUpdateTime> {
	public:
		auto oldest() const {
			return cbegin();
		}
		auto latest() const {
			return crbegin();
		}
	};

	class Key {
	public:
		friend class ModuleRouter;
		friend class RegistrarDbRedisAsync;

		// A null pointer or an empty AOR leads to an empty key.
		explicit Key(const url_t* aor, bool useGlobalDomain);
		explicit Key(const SipUri& aor, bool useGlobalDomain) : Key(aor.get(), useGlobalDomain) {
		}

		std::string toRedisKey() const {
			return "fs:" + mWrapped;
		}
		SipUri toSipUri() const;
		std::string toString() && {
			return std::move(mWrapped);
		}
		const std::string& asString() const {
			return mWrapped;
		}

		bool operator==(const Key& other) const {
			return mWrapped == other.mWrapped;
		}

		friend std::ostream& operator<<(std::ostream& out, const Key& self) {
			return out << self.mWrapped;
		}

	private:
		explicit Key(std::string&& raw) : mWrapped(std::move(raw)) {
		}
		explicit Key(const std::string_view& raw) : mWrapped(raw) {
		}

		std::string mWrapped;
	};

	// Retain the configuration parameters used by the record class.
	class Config {
	public:
		explicit Config(const ConfigManager& cfg);

		int getMaxContacts() const {
			return mMaxContacts;
		}
		const std::list<std::string>& getLineFieldNames() const {
			return mLineFieldNames;
		}
		const std::string& messageExpiresName() const {
			return mMessageExpiresName;
		}
		bool assumeUniqueDomains() const {
			return mAssumeUniqueDomains;
		}
		bool useGlobalDomain() const {
			return mUseGlobalDomain;
		}

	private:
		int mMaxContacts;
		std::list<std::string> mLineFieldNames;
		std::string mMessageExpiresName;
		bool mAssumeUniqueDomains;
		bool mUseGlobalDomain;
	};

	explicit Record(const SipUri& aor, const Config& recordConfig);
	explicit Record(SipUri&& aor, const Config& recordConfig);
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

	void clean(const std::shared_ptr<ContactUpdateListener>& listener);

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

	void print(std::ostream& stream) const;
	bool isEmpty() const {
		return mContacts.empty();
	}
	const Key& getKey() const {
		return mKey;
	}
	int count() {
		return mContacts.size();
	}
	const Contacts& getExtendedContacts() const {
		return mContacts;
	}
	Contacts& getExtendedContacts() {
		return mContacts;
	}
	const Config& getConfig() const {
		return mConfig;
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
	time_t latestExpire() const;
	time_t latestExpire(std::function<bool(const url_t*)>& predicate) const;
	static std::list<std::string> route_to_stl(const sip_route_s* route);
	void appendContactsFrom(const std::shared_ptr<Record>& src);
	bool haveOnlyStaticContacts() const {
		return mOnlyStaticContacts;
	}
	bool isSame(const Record& other) const;

	std::string extractUniqueId(const sip_contact_t* contact);

private:
	enum class ContactMatch {
		Skip,           // Does not match the newly registered contact. Nothing to do.
		EraseAndNotify, // Update or Remove
		ForceErase,     // Service clean up
	};

	static ContactMatch matchContacts(const ExtendedContact& existing, const ExtendedContact& neo);
	static void eliminateAmbiguousContacts(std::list<std::unique_ptr<ExtendedContact>>& extendedContacts);
	ChangeSet removeInvalidContacts();

	sofiasip::Home mHome;
	Contacts mContacts;
	SipUri mAor;
	Key mKey;

	bool mIsDomain = false; /*is a domain registration*/
	Config mConfig;
	bool mOnlyStaticContacts = true;
};

inline std::ostream& operator<<(std::ostream& strm, const Record& record) {
	record.print(strm);
	return strm;
}

} // namespace flexisip
