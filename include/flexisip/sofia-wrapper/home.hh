/*
    Flexisip, a flexible SIP proxy server with media capabilities.
    Copyright (C) 2010-2023 Belledonne Communications SARL, All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <cctype>
#include <initializer_list>
#include <ostream>
#include <sstream>
#include <string_view>
#include <type_traits>

#include "sofia-sip/sip_protos.h"
#include "sofia-sip/su_alloc.h"

#include "flexisip/template-metaprogramming.hh"

namespace sofiasip {

/**
 * A wrapper for SofiaSip's su_home_t type.
 */
class Home {
public:
	Home() noexcept {
		su_home_init(mHome);
	}
	Home(const Home& src) = delete;
	Home(Home&& src) noexcept : Home() {
		su_home_move(mHome, src.mHome);
	}
	~Home() noexcept {
		su_home_deinit(mHome);
	}

	Home& operator=(const Home& src) = delete;
	Home& operator=(Home&& src) noexcept {
		reset();
		su_home_move(mHome, src.mHome);
		return *this;
	}

	su_home_t* home() noexcept {
		return mHome;
	}
	const su_home_t* home() const noexcept {
		return mHome;
	}

	// Free all the buffers which are referenced by this Home.
	void reset() noexcept {
		su_home_deinit(mHome);
		su_home_init(mHome);
	}

	void* alloc(std::size_t size) noexcept {
		return su_alloc(mHome, size);
	}
	void free(void* data) noexcept {
		return su_free(mHome, data);
	}

	char* vsprintf(char const* fmt, va_list ap) noexcept {
		return su_vsprintf(mHome, fmt, ap);
	}
	template <typename... Args>
	char* sprintf(const char* fmt, Args&&... args) noexcept {
		return su_sprintf(mHome, fmt, args...);
	}

	// Equivalent to sip_contact_create
	template <typename... IterableOrStreamable>
	sip_contact_t* createContact(const std::string_view& url, IterableOrStreamable&&... params) {
		std::ostringstream contact{};
		contact << '<' << url << '>';
		(appendParam(contact, params), ...);
		return sip_contact_make(mHome, contact.str().c_str());
	}

private:
	template <typename IterableOfStreamable,
	          typename = std::enable_if_t<type::is_iterable<IterableOfStreamable>>,
	          typename = std::enable_if_t<!type::is_streamable<IterableOfStreamable>>>
	static void appendParam(std::ostream& contact, const IterableOfStreamable& params) {
		for (const auto& param : params) {
			appendParam(contact, param);
		}
	}
	template <typename Streamable, typename = std::enable_if_t<type::is_streamable<Streamable>>>
	static void appendParam(std::ostream& contact, const Streamable& param) {
		contact << ';' << param;
	}

	su_home_t mHome[1]{};
};

} // namespace sofiasip
