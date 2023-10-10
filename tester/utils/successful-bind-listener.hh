/** Copyright (C) 2010-2023 Belledonne Communications SARL
 *  SPDX-License-Identifier: AGPL-3.0-or-later
 */

#pragma once

#include <memory>

#include "bctoolbox/tester.h"

#include "flexisip/registrar/registar-listeners.hh"

namespace flexisip::tester {

class SuccessfulBindListener : public ContactUpdateListener {
public:
	std::shared_ptr<Record> mRecord{nullptr};

	virtual void onRecordFound(const std::shared_ptr<Record>& r) override {
		mRecord = r;
	}
	void onError(const SipStatus&) override {
		BC_FAIL("This test doesn't expect an error response");
	}
	void onInvalid(const SipStatus&) override {
		BC_FAIL("This test doesn't expect an invalid response");
	}
	void onContactUpdated(const std::shared_ptr<ExtendedContact>&) override {
		BC_FAIL("This test doesn't expect a contact to be updated");
	}
};

} // namespace flexisip::tester
