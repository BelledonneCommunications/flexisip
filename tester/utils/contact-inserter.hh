/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
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
	const std::string_view contact = "";
	const std::string_view uniqueId = "";
};

class ContactInsertedListener : public ContactUpdateListener {
public:
	std::unordered_set<std::string> contactsToBeInserted;

	void onRecordFound(const std::shared_ptr<Record>& r) override;
	void onError(const SipStatus&) override {
		BC_FAIL("This test doesn't expect an error response on insertion");
	}
	void onInvalid(const SipStatus&) override {
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
