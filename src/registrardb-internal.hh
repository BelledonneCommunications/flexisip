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

#pragma once

#include <string>
#include <unordered_map>

#include <sofia-sip/sip.h>

#include "registrar/extended-contact.hh"
#include "registrar/record.hh"
#include "registrar/registrar-db.hh"

namespace flexisip {

class RegistrarDbInternal : public RegistrarDbBackend {
public:
	RegistrarDbInternal(const Record::Config& recordConfig,
	                    LocalRegExpire& localRegExpire,
	                    std::function<void(const Record::Key&, const std::string&)> notify);
	void clearAll();

	void fetchExpiringContacts(time_t startTimestamp,
	                           float threshold,
	                           std::function<void(std::vector<ExtendedContact>&&)>&& callback) const override;

	/**
	 * Read-only access to the stored records. As of 2023-07-05, only used in tests
	 */
	const auto& getAllRecords() const {
		return castToConst(mRecords);
	}

	bool isWritable() const override {
		return true;
	};

	void doBind(const sofiasip::MsgSip& msg,
	            const BindingParameters& parameters,
	            const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doClear(const sofiasip::MsgSip& msg, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetch(const SipUri& url, const std::shared_ptr<ContactUpdateListener>& listener) override;
	void doFetchInstance(const SipUri& url,
	                     const std::string& uniqueId,
	                     const std::shared_ptr<ContactUpdateListener>& listener) override;
	void subscribe(const Record::Key&) override{};
	void unsubscribe(const Record::Key&) override{};
	void publish(const Record::Key& topic, const std::string& uid) override;

private:
	bool errorOnTooMuchContactInBind(const sip_contact_t* sip_contact, const std::string& key);

	const Record::Config& mRecordConfig;
	LocalRegExpire& mLocalRegExpire;
	std::unordered_map<std::string, std::shared_ptr<Record>> mRecords{};
	std::function<void(const Record::Key&, const std::string&)> mNotifyContactListener;
};

} // namespace flexisip
