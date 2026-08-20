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

#pragma once

#include "belle-sip/belle-sip.h"

namespace flexisip {

class BellesipTransaction {
public:
	BellesipTransaction() = default;
	explicit BellesipTransaction(belle_sip_client_transaction_t* transaction);
	BellesipTransaction(const BellesipTransaction& other);
	BellesipTransaction(BellesipTransaction&& other) noexcept;

	~BellesipTransaction();

	BellesipTransaction& operator=(const BellesipTransaction& other);
	BellesipTransaction& operator=(BellesipTransaction&& other) noexcept;
	explicit operator bool() const noexcept;

	belle_sip_transaction_state_t getState() const;
	belle_sip_request_t* createCancel() const;
	belle_sip_client_transaction_t* get() const;

private:
	belle_sip_client_transaction_t* mTransaction{nullptr};
};

} // namespace flexisip