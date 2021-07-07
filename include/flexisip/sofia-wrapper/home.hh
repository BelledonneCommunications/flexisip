/*
	Flexisip, a flexible SIP proxy server with media capabilities.
	Copyright (C) 2010-2020  Belledonne Communications SARL, All rights reserved.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cctype>

#include <sofia-sip/su_alloc.h>

namespace sofiasip {

/**
 * A wrapper for SofiaSip's su_home_t type.
 */
class Home {
public:
	Home() noexcept {su_home_init(&mHome);}
	Home(const Home &src) = delete;
	Home(Home &&src) noexcept : Home() {su_home_move(&mHome, &src.mHome);}
	~Home() noexcept {su_home_deinit(&mHome);}

	Home &operator=(const Home &src) = delete;
	Home &operator=(Home &&src) noexcept {
		reset();
		su_home_move(&mHome, &src.mHome);
		return *this;
	}

	su_home_t* home() noexcept {return &mHome;}
	const su_home_t* home() const noexcept {return &mHome;}

	// Free all the buffers which are referenced by this Home.
	void reset() noexcept {
		su_home_deinit(&mHome);
		su_home_init(&mHome);
	}

	void* alloc(std::size_t size) noexcept {return su_alloc(&mHome, size);}
	void free(void *data) noexcept {return su_free(&mHome, data);}

	char* vsprintf(char const* fmt, va_list ap) noexcept {
		return su_vsprintf(&mHome, fmt, ap);
	}
	template <typename... Args> char* sprintf(const char* fmt, Args&&... args) noexcept {
		return su_sprintf(&mHome, fmt, args...);
	}

private:
	su_home_t mHome{};
};

} // end of sofiasip namespace
