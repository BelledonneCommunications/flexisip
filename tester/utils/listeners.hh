/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2025 Belledonne Communications SARL, All rights reserved.

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

#include "flexisip/registrar/registar-listeners.hh"

namespace flexisip::tester {

class ContactRegisteredCallback : public ContactRegisteredListener {
public:
	template <typename TCallback>
	explicit ContactRegisteredCallback(TCallback&& callback) : mCallback(std::forward<TCallback>(callback)){};

private:
	void onContactRegistered(const std::shared_ptr<Record>& r, const std::string& uid) override {
		mCallback(r, uid);
	}

	std::function<void(const std::shared_ptr<Record>&, const std::string&)> mCallback;
};

} // namespace flexisip::tester