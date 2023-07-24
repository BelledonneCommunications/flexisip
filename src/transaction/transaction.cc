/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

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

#include "transaction.hh"

using namespace flexisip;

Transaction::Property Transaction::_getProperty(const std::string& name) const noexcept {
	auto it = mProperties.find(name);
	if (it != mProperties.cend()) {
		return it->second;
	} else {
		auto wit = mWeakProperties.find(name);
		if (wit == mWeakProperties.cend()) return Property{};
		const auto& prop = wit->second;
		return Property{prop.value.lock(), prop.type};
	}
}