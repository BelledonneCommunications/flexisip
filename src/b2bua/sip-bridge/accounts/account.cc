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

#include "account.hh"

namespace flexisip::b2bua::bridge {
using namespace std;

Account::Account(const std::shared_ptr<linphone::Account>& account, uint16_t freeSlots, std::string_view alias)
    : account(account), freeSlots(freeSlots), mAlias(alias) {
}

bool Account::isAvailable() const {
	if (freeSlots == 0) {
		return false;
	}
	if (account->getParams()->registerEnabled() && account->getState() != linphone::RegistrationState::Ok) {
		return false;
	}
	return true;
}

const std::shared_ptr<linphone::Account>& Account::getLinphoneAccount() const {
	return account;
}
const SipUri& Account::getAlias() const {
	return mAlias;
}
decltype(Account::freeSlots) Account::getFreeSlotsCount() const {
	return freeSlots;
}

void Account::takeASlot() {
	--freeSlots;
}
void Account::releaseASlot() {
	++freeSlots;
}

} // namespace flexisip::b2bua::bridge