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

#include "bctoolbox/tester.h"

#include <memory>
#include <string_view>

#include "flexisip/registrar/registar-listeners.hh"

#include "flexisip/utils/sip-uri.hh"
#include "registrar/binding-parameters.hh"
#include "registrar/registrar-db.hh"

namespace flexisip::tester {

struct ContactInsertArgs {
	const std::string_view contact{};
	const std::string_view uniqueId{};
};

class ContactInsertedListener : public ContactUpdateListener {
public:
	std::unordered_set<std::string> contactsToBeInserted;

	void onRecordFound(const std::shared_ptr<Record>& r) override;
	void onError() override {
		BC_FAIL("This test doesn't expect an error response on insertion");
	}
	void onInvalid() override {
		BC_FAIL("This test doesn't expect an invalid response on insertion");
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		BC_FAIL("This test doesn't expect contacts to be updated on insertion");
	}
};

class AcceptUpdatesListener : public ContactInsertedListener {
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
	}
};

// Insert Contacts into the Registrar
class ContactInserter {
public:
	ContactInserter(RegistrarDb& regDb,
	                std::shared_ptr<ContactInsertedListener>&& = std::make_shared<ContactInsertedListener>());

	ContactInserter& insert(const ContactInsertArgs& = {});

	bool finished() const {
		return mListener->contactsToBeInserted.empty();
	}

	ContactInserter& withUniqueId(bool enabled) {
		mGenerateUniqueId = enabled;
		if (!enabled) withGruu(false);
		return *this;
	}
	ContactInserter& withGruu(bool enabled) {
		mParameters.withGruu = enabled;
		if (enabled) withUniqueId(true);
		return *this;
	}
	ContactInserter& setExpire(std::chrono::seconds expire) {
		mParameters.globalExpire = expire.count();
		return *this;
	}
	ContactInserter& setPath(const std::vector<std::string>& path) {
		mParameters.path = path;
		return *this;
	}
	template <typename T>
	ContactInserter& setAor(T&& aor) {
		mAor = SipUri(std::forward<T>(aor));
		return *this;
	}
	ContactInserter& setContactParams(std::vector<std::string_view>&& params) {
		mContactParams = std::move(params);
		return *this;
	}

private:
	RegistrarDb& mRegDb;
	BindingParameters mParameters{};
	SipUri mAor;
	std::vector<std::string_view> mContactParams{};
	std::shared_ptr<ContactInsertedListener> mListener;
	std::uint16_t mCount = 0;
	bool mGenerateUniqueId : 1;
};

} // namespace flexisip::tester
