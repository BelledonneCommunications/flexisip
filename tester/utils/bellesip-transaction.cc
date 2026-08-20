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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "bellesip-transaction.hh"

namespace flexisip {

BellesipTransaction::BellesipTransaction(belle_sip_client_transaction_t* transaction) : mTransaction(transaction) {
	if (mTransaction) belle_sip_object_ref(mTransaction);
}

BellesipTransaction::BellesipTransaction(const BellesipTransaction& other) : BellesipTransaction(other.mTransaction) {}

BellesipTransaction::BellesipTransaction(BellesipTransaction&& other) noexcept : mTransaction(other.mTransaction) {
	other.mTransaction = nullptr;
}

BellesipTransaction& BellesipTransaction::operator=(const BellesipTransaction& other) {
	if (this == &other) return *this;

	auto* transaction = other.mTransaction;
	if (transaction) belle_sip_object_ref(transaction);
	if (mTransaction) belle_sip_object_unref(mTransaction);
	mTransaction = transaction;
	return *this;
}

BellesipTransaction& BellesipTransaction::operator=(BellesipTransaction&& other) noexcept {
	if (this == &other) return *this;

	if (mTransaction) belle_sip_object_unref(mTransaction);
	mTransaction = other.mTransaction;
	other.mTransaction = nullptr;
	return *this;
}

BellesipTransaction::~BellesipTransaction() {
	if (mTransaction) belle_sip_object_unref(mTransaction);
}

belle_sip_transaction_state_t BellesipTransaction::getState() const {
	if (!mTransaction) return BELLE_SIP_TRANSACTION_TERMINATED;
	return belle_sip_transaction_get_state(BELLE_SIP_TRANSACTION(mTransaction));
}

belle_sip_request_t* BellesipTransaction::createCancel() const {
	if (!mTransaction) return nullptr;
	return belle_sip_client_transaction_create_cancel(mTransaction);
}

belle_sip_client_transaction_t* BellesipTransaction::get() const {
	return mTransaction;
}

BellesipTransaction::operator bool() const noexcept {
	return mTransaction != nullptr;
}

} // namespace flexisip