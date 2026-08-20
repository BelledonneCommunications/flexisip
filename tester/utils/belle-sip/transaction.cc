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

#include "transaction.hh"

namespace belle_sip {

Transaction::Transaction(belle_sip_client_transaction_t* transaction) : mTransaction(transaction) {
	if (mTransaction) belle_sip_object_ref(mTransaction);
}

Transaction::Transaction(const Transaction& other) : Transaction(other.mTransaction) {}

Transaction::Transaction(Transaction&& other) noexcept : mTransaction(other.mTransaction) {
	other.mTransaction = nullptr;
}

Transaction& Transaction::operator=(const Transaction& other) {
	if (this == &other) return *this;

	auto* transaction = other.mTransaction;
	if (transaction) belle_sip_object_ref(transaction);
	if (mTransaction) belle_sip_object_unref(mTransaction);
	mTransaction = transaction;
	return *this;
}

Transaction& Transaction::operator=(Transaction&& other) noexcept {
	if (this == &other) return *this;

	if (mTransaction) belle_sip_object_unref(mTransaction);
	mTransaction = other.mTransaction;
	other.mTransaction = nullptr;
	return *this;
}

Transaction::~Transaction() {
	if (mTransaction) belle_sip_object_unref(mTransaction);
}

belle_sip_transaction_state_t Transaction::getState() const {
	if (!mTransaction) return BELLE_SIP_TRANSACTION_TERMINATED;
	return belle_sip_transaction_get_state(BELLE_SIP_TRANSACTION(mTransaction));
}

belle_sip_request_t* Transaction::createCancel() const {
	if (!mTransaction) return nullptr;
	return belle_sip_client_transaction_create_cancel(mTransaction);
}

belle_sip_client_transaction_t* Transaction::get() const {
	return mTransaction;
}

Transaction::operator bool() const noexcept {
	return mTransaction != nullptr;
}

} // namespace belle_sip