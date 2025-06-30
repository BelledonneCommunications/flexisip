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

#include "home.hh"

namespace sofiasip::utility {

void Home::Deleter::operator()(Home* home) noexcept {
	::su_home_unref(home);
}

int Home::setDestructor(void (*destructor)(void*)) {
	return ::su_home_destructor(this, destructor);
}

Home* Home::wrap(su_home_t* raw) {
	static_assert(sizeof(Home) == sizeof(*raw));
	static_assert(alignof(Home) == alignof(typeof(*raw)));
	static_assert(std::is_base_of_v<typeof(*raw), Home>);
	return reinterpret_cast<Home*>(raw);
}

} // namespace sofiasip::utility