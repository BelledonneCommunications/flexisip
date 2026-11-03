/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2026 Belledonne Communications SARL, All rights reserved.

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

#include <memory>
#include <string>

#include "b2bua/sip-bridge/accounts/account.hh"
#include "linphone++/account.hh"
#include "linphone++/factory.hh"
#include "utils/test-patterns/test.hh"

namespace flexisip::tester {

inline std::shared_ptr<const linphone::Address> makeAddress(const std::string& uri) {
	const auto address = linphone::Factory::get()->createAddress(uri);
	BC_HARD_ASSERT(address != nullptr);
	return address;
}

inline std::shared_ptr<flexisip::b2bua::bridge::Account>
makeAccount(const std::shared_ptr<linphone::Core>& core, const std::string& uri, std::string_view alias) {
	const auto factory = linphone::Factory::get();

	const auto accountAddress = makeAddress(uri);

	auto accountParams = core->createAccountParams();
	BC_HARD_ASSERT(accountParams != nullptr);

	accountParams->setIdentityAddress(accountAddress);
	// A server address is required for the account to be addable to the core.
	accountParams->setServerAddress(factory->createAddress("sip:external.example.org"));

	auto linphoneAccount = core->createAccount(accountParams);
	BC_HARD_ASSERT(linphoneAccount != nullptr);
	linphoneAccount->setContactAddress(accountAddress);
	BC_HARD_ASSERT_CPP_EQUAL(core->addAccount(linphoneAccount), 0);
	return make_shared<flexisip::b2bua::bridge::Account>(linphoneAccount, 0x7E57, alias);
}

} // namespace flexisip::tester